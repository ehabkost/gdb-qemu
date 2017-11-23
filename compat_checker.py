#!/usr/bin/env python2.7
#
# QEMU compatibility code checker
#
# Copyright (C) 2017    Red Hat Inc
#
# Author:
#   Eduardo Habkost <ehabkost@redhat.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
##############################################################################
import sys, argparse, logging, subprocess, json, os, platform, socket
import difflib, pprint, tempfile, shutil, re, copy
import qmp
from logging import DEBUG, INFO, WARN, ERROR, CRITICAL

MYDIR = os.path.dirname(__file__)
GDB_EXTRACTOR = os.path.join(MYDIR, 'gdb-extract-qemu-info.py')

logger = logging.getLogger('compat-checker')
dbg = logger.debug

# devices that can make gdb crash if querying instance properties:
UNSAFE_DEVICES = set(['i440FX-pcihost', 'pc-dimm', 'q35-pcihost'])

class ValidationContext:
    """Object carrying information about the context where we're validating information

    Attributes:
    * binary1: First binary/dump being verified.
    * binary2: Second binary/dump being verified.
    * machinename: Machine type name.
    """
    def __init__(self, binary1=None, binary2=None, machinename=None):
        self.binary1 = binary1
        self.binary2 = binary2
        self.machinename = machinename

    def __str__(self):
        if self.binary1 and self.binary2:
            r = '%s vs %s' % (self.binary1, self.binary2)
        elif self.binary1:
            r = '%s' % (self.binary1)
        if self.machinename:
            r += ': %s' % (self.machinename)
        return r

    def log(self, loglevel, msg, *args):
        """Log a simple human-readable message (useful for debugging)"""
        msg = msg % args
        logger.log(loglevel, '%s: %s', self, msg)

    def single_binary_ctx(self, b):
        """Return context for validations involving only a single binary"""
        r = copy.copy(self)
        r.binary1 = b
        r.binary2 = None
        return r

    def b1_ctx(self):
        return self.single_binary_ctx(self.binary1)

    def b2_ctx(self):
        return self.single_binary_ctx(self.binary2)

    def report_result(self, loglevel, msg, *args):
        """Report result of a specific validation

        TODO: replace msg+args with a dictionary containing result information.
        """
        self.log(loglevel, msg, *args)

def apply_compat_props(binary, machinename, d, compat_props):
    values = {}
    """Apply a list of compat_props to a d[driver][property] dictionary"""
    for cp in compat_props:
        key = (cp['driver'], cp['property'])
        if values.get(key) == cp['value']:
            logger.warn("%s:%s: duplicate compat property: %s.%s=%s", binary, machinename, cp['driver'], cp['property'], cp['value'])
        values[key] = cp['value']
        # translate each compat property to all the subtypes
        t = cp['driver']
        qmp_info = binary.get_one_request('qmp-info') or {}
        hierarchy = qmp_info.get('devtype-hierarchy', {})
        subtypes = hierarchy.get(t, [{'name':t}])
        dbg("subtypes: %r", subtypes)
        for subtype in  subtypes:
            d.setdefault(subtype['name'], {})[cp['property']] = cp['value']

def devtype_has_full_prop_info(devtype):
    return ('props' in devtype) and ('instance_props' in devtype) and len(devtype['instance_props']) > 0

def get_devtype_property_info(devtype, propname):
    if devtype is None:
        return None

    r = None
    for prop in devtype.get('props', []):
        if prop['name'] == propname and 'defval' in prop:
            r = dict(name=prop['name'],
                     type=prop.get('info', {}).get('name'),
                     defval=prop['defval'])
            break

    ir = None
    for prop in devtype.get('instance_props', []):
        if prop['name'] == propname and 'value' in prop:
            ir = dict(name=prop['name'],
                      type=prop['type'],
                      defval=prop['value'])
            break

    if ir is not None and r is not None:
        assert r['name'] == ir['name']
        if r['type'] != ir['type']:
            logger.error("dc->props and instance props disagree about type of %s", propname)
        if r['defval'] != ir['defval']:
            logger.debug("dc->props and instance props disagree about default value of %s", propname)
        # instance_props are more reliable, because instance_init can override the
        # default value set in dc->props
        return ir
    elif ir is not None:
        return ir
    else:
        return r

KNOWN_ENUMS = {
    'FdcDriveType': ["144", "288", "120", "none", "auto"],
    'OnOffAuto': ['on', 'off', 'auto']
}

def parse_property_value(prop, value):
    """Parse a string according to property type

    If value is None, simply return None.
    """
    if value is None:
        return None

    t = prop['type']
    if t is not None and re.match('u?int(|8|16|32|64)', t):
        if type(value) in [str, unicode]:
            value = int(value, base=0)
        return value
    elif t == 'bool' or t == 'boolean':
        assert value in ['on', 'yes', 'true', 'off', 'no', 'false', True, False], "Invalid boolean value: %s" % (value)
        return value in ['on', 'yes', 'true', True]
    elif t == 'str' or t == 'string':
        return str(value)
    elif t in KNOWN_ENUMS:
        assert value in KNOWN_ENUMS[t]
        return value
    else:
        raise Exception("Unsupported property type %s" % (t))

def try_bool(v):
    """Try to convert a value to a boolean, keep it untouched otherwise"""
    if v in [0, False, '0', 'off']:
        return False
    elif v in [1, True, '1', 'on']:
        return True
    else:
        return v

def bool_to_str(v):
    """Convert boolean values to str, keep anything else untouched"""
    if v == False:
        return 'off'
    elif v == True:
        return 'on'
    else:
        return v

def compare_properties(p1, v1, p2, v2):
    """Compare two property values, with some hacks to handle type mismatches"""

    # we need a special hack for OnOffAuto, because:
    # 1) intel-hda.msi had changed its type from uint32_to OnOffAuto
    # 2) virtio-pci.disable-legacy also changed from bool to OnOffAuto
    if p1 is not None \
       and p1.get('type') == 'OnOffAuto':
       v2 = bool_to_str(try_bool(v2))
    if p2 is not None \
       and p2.get('type') == 'OnOffAuto':
       v1 = bool_to_str(try_bool(v1))


    dbg("comparing %r:%r and %r:%r", v1, p1, v2, p2)

    # try some tricks if there's absolutely no type information:
    if p1 is None and p2 is None:
        if (type(v1) is bool or type(v2) is bool):
            v1 = try_bool(v1)
            v2 = try_bool(v2)
        else:
            # try string comparison if we really don't know anything about
            # the property:
            v1 = str(v1)
            v2 = str(v2)

    # if property type is unknown on one QEMU binary, try using the
    # type information from the other binary:
    if p1 is not None and p2 is None:
        v2 = parse_property_value(p1, v2)
    if p2 is not None and p1 is None:
        v1 = parse_property_value(p2, v1)

    return v2 == v1

def get_devtype_property_default_value(devtype, propname):
    """Extract default value for a property, based on device-type dictionary"""
    if devtype is None:
        return None

    r = None
    for prop in devtype.get('props', []):
        if prop['name'] == propname and 'defval' in prop:
            r = prop['defval']

    for prop in devtype.get('instance_props', []):
        if prop['name'] == propname and 'value' in prop:
            if r is not None:
                assert r == prop['value']
            return prop['value']

    return r

AUTO = 0
BINARY = 1
JSON = 2

class QEMUBinaryInfo:
    def __init__(self, path, filetype=AUTO):
        self.path = path
        self.type = filetype
        self._process = None
        self._tmpdir = None
        self._qmp = None
        self.keep_tmpdata = False

    def run_gdb_extractor(self, args, machines, devices=[]):
        outfile = os.path.join(self.tmpdir(), 'gdb-extractor.json')
        cmd = ['gdb', '-q', '-P', GDB_EXTRACTOR]
        cmd.extend(['-o', outfile])
        for m in machines:
            cmd.extend(['-M', m])
        for d in devices:
            cmd.extend(['-D', d])
            if d in UNSAFE_DEVICES:
                cmd.extend(['--unsafe-device', d])
        if args.loglevel <= DEBUG:
            cmd.append('-d')
        cmd.append(self.path)
        subprocess.call(cmd)
        try:
            r = json.load(open(outfile))
        except KeyboardInterrupt:
            raise
        except:
            logger.error("Error loading JSON")
            logger.error("tmp data kept at: %s", outfile)
            self.keep_tmpdata = True
            raise
        return r

    def get_stdout(self, *args):
        """Helper to simply run QEMU and get stdout output"""
        try:
            return subprocess.Popen([self.path] + list(args),
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT).communicate()[0]
        except KeyboardInterrupt:
            raise
        except:
            return None

    def get_rpm_package(self):
        # use shell to ensure we will just get an error message if RPM
        # is not available
        return subprocess.Popen(['sh', '-c', "rpm -qf %s" % (self.path)],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT).communicate()[0]

    def tmpdir(self):
        if not self._tmpdir:
            self._tmpdir = tempfile.mkdtemp()
        return self._tmpdir

    def get_qmp(self):
        if self._qmp is not None:
            return self._qmp

        assert self.path
        sockfile = os.path.join(self.tmpdir(), 'monitor-sock')
        self._qmp = qmp.QEMUMonitorProtocol(sockfile, server=True)
        args = [self.path, '-S', '-M', 'none', '-display', 'none', '-qmp', 'unix:%s' %(sockfile)]
        self._process = subprocess.Popen(args, shell=False)
        self._qmp.accept()
        return self._qmp

    def terminate(self):
        if self._qmp:
            self._qmp.cmd('quit')
            self._qmp.close()
            self._qmp = None
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
        if self._tmpdir and not self.keep_tmpdata:
            shutil.rmtree(self._tmpdir)
            self._tmpdir = None

    def __del__(self):
        self.terminate()

    def query_full_devtype_hierarchy(self):
        qmp = self.get_qmp()
        alltypes =qmp.command('qom-list-types', implements='device', abstract=True)
        implements = {}
        for d in alltypes:
            implements[d['name']] = qmp.command('qom-list-types', implements=d['name'])
        return implements

    def query_qmp_info(self):
        qmp = self.get_qmp()
        machines = qmp.command('query-machines')
        devices = qmp.command('qom-list-types', implements='device', abstract=True)
        cpu_models = qmp.command('query-cpu-definitions')
        devtype_hierarchy = self.query_full_devtype_hierarchy()
        return {'machines':machines, 'devices':devices, 'cpu-models':cpu_models,
                'devtype-hierarchy':devtype_hierarchy }

    def append_raw_item(self, reqtype, result, args=[]):
        self.raw_data.append(dict(request=[reqtype] + list(args), result=result))

    def all_devtypes(self):
        return [d['name'] for d in self.get_one_request('qmp-info')['devices']]

    def extract_binary_data(self, args):
        self.raw_data = []
        version_info = {'help': self.get_stdout('-version'),
                        'rpm-qf': self.get_rpm_package() }
        try:
            version_info['os-release'] = open('/etc/os-release').read()
        except IOError:
            pass
        self.append_raw_item('version', version_info)
        self.append_raw_item('help', self.get_stdout('-help'))
        self.append_raw_item('device-help', self.get_stdout('-device', 'help'))
        self.append_raw_item('machine-help', self.get_stdout('-machine', 'help'))
        self.append_raw_item('cpu-help', self.get_stdout('-cpu', 'help'))
        self.append_raw_item('hostname', {'platform.node': platform.node(),
                                          'gethostname': socket.gethostname()})
        qmp_info = self.query_qmp_info()
        self.append_raw_item('qmp-info', qmp_info)
        if not args.machines:
            machines = sorted([m['name'] for m in qmp_info['machines']])
        else:
            machines = args.machines
        if args.devices:
            devices = args.devices
        else:
            devices = sorted(self.all_devtypes())
        self.raw_data.extend(self.run_gdb_extractor(args, machines, devices))

    def load_data_file(self, json_data=None):
        if json_data is None:
            json_data = json.load(open(self.path))
        self.raw_data = json_data

    def load_data(self, args):
        if self.type == BINARY:
            self.extract_binary_data(args)
        elif self.type == JSON:
            self.load_data_file()
        else:
            # autodetect:
            try:
                self.load_data_file()
                self.type = JSON
            except KeyboardInterrupt:
                raise
            except:
                pass

            if self.type != JSON:
                self.extract_binary_data(args)
                self.type = BINARY

    def list_requests(self, reqtype):
        for i in self.raw_data:
            if i['request'][0] == reqtype:
                yield i

    def get_one_request(self, reqtype, *args):
        for m in self.list_requests(reqtype):
            if m['request'][1:] == list(args):
                return m.get('result')

    def get_machine(self, machinename):
        return self.get_one_request('machine', machinename)

    def get_devtype(self, devtype):
        return self.get_one_request('device-type', devtype)

    def available_machines(self):
        for m in self.list_requests('machine'):
            yield m['request'][1]

    def qemu_version(self):
        v = self.get_one_request('version')
        if v is None:
            return None
        vhelp = v['help']
        m = re.search(r'QEMU emulator version ([0-9.]+)', vhelp, re.M)
        if m is None:
            return None
        return m.group(1)

    def __str__(self):
        return self.path

def build_omitted_prop_dict(binary):
    """Build list of property values for non-existing properties

    This builds a dictionary containing the assumed values for properties
    that don't exist in the existing binary (i.e. if it is a QEMU version
    that is old and didn't have the property yet). The returned dictionary
    will contain the value required to emulate the behavior QEMU had when
    the property didn't exist yet.
    """
    OMITTED_PROP_VALUES = [
        ('pci-device',           'x-pcie-extcap-init',            False),
        ('pci-device',           'x-pcie-lnksta-dllla',           False),
        ('x86_64-cpu',           'kvm-no-smi-migration',           True),
        ('i386-cpu',             'kvm-no-smi-migration',           True),
        ('x86_64-cpu',           'full-cpuid-auto-level',         False),
        ('i386-cpu',             'full-cpuid-auto-level',         False),
        # tcg-cpuid implemented by commit 1ce36bfe6424243082d3d7c2330e1a0a4ff72a43:
        ('x86_64-cpu',           'tcg-cpuid',         False),
        ('i386-cpu',             'tcg-cpuid',         False),
        ('x86_64-cpu',           'cpuid-0xb',                     False),
        ('i386-cpu',             'cpuid-0xb',                     False),
        ('x86_64-cpu',           'l3-cache',                      False),
        ('i386-cpu',             'l3-cache',                      False),
        ('x86_64-cpu',           'fill-mtrr-mask',                False),
        ('i386-cpu',             'fill-mtrr-mask',                False),
        # commit 6c69dfb67e84747cf071958594d939e845dfcc0c:
        ('x86_64-cpu',           'x-hv-max-vps', 0x40),
        ('i386-cpu',             'x-hv-max-vps', 0x40),
        # commit 9954a1582e18b03ddb66f6c892dccf2c3508f4b2:
        ('x86_64-cpu',           'vmware-cpuid-freq',             False),
        ('i386-cpu',             'vmware-cpuid-freq',             False),
        # commit e265e3e48049fbece9eaf536aa00ca41aa3c54d0:
        ('x86_64-cpu',           'host-cache-info',                True),
        ('i386-cpu',             'host-cache-info',                True),
        # CPU feature flags that were always off when we introduced them:
        ('x86_64-cpu',           'arat',                          False),
        ('i386-cpu',             'arat',                          False),
        ('x86_64-cpu',           'rdrand',                        False),
        ('i386-cpu',             'rdrand',                        False),
        ('x86_64-cpu',           'f16c',                          False),
        ('i386-cpu',             'f16c',                          False),

        # * VMX was disabled on all CPU models when we added CPU
        #   feature properties (commit 38e5c119c2925812bd441450ab9e5e00fc79e662
        #   v2.4.0-rc0~101^2~1).
        # * However, it was enabled on core2duo and coreduo between
        #   commit 8560efed6a72a816c0115f41ddb9d79f7ce63f28 (v0.13.0-rc0~1093)
        #   and commit e93abc147fa628650bdbe7fd57f27462ca40a3c2 (v2.2.0-rc0~5^2~1).
        # * Probably it is possible to work around this by looking at
        #   the "feature-words" property
        #('x86_64-cpu',           'vmx',                           ???),
        #('i386-cpu',             'vmx',                           ???),

        # * VME was already enabled on all CPU models when we added CPU
        #   feature properties (commit 38e5c119c2925812bd441450ab9e5e00fc79e662
        #   v2.4.0-rc0~101^2~1).
        # * However, VME was always disabled on TCG mode and this wasn't
        #   reported throught the QOM properties until
        #   commit 04d99c3c61f4bdc0450dbeb6512b6dd743baca65 (v2.8.0-rc0~74^2~18)
        # * To make it worse, VME was disabled on all CPU models until
        #   commit b3a4f0b1a072a467d003755ca0e55c5be38387cb (v2.3.0-rc0~137^2~13),
        # * Probably it is possible to work around this by looking at
        #   the "feature-words" property
        #('x86_64-cpu',           'vme',                          ???),
        #('i386-cpu',             'vme',                          ???),

        # * ABM was already enabled on qemu64, phenom, kvm64, Opteron_G3,
        #   Opteron_G4, and Opteron_G5 when we added CPU feature properties
        #   (commit 38e5c119c2925812bd441450ab9e5e00fc79e662 v2.4.0-rc0~101^2~1)
        # * Note that we have removed ABM from qemu64 on
        #   commit 711956722c6764336f8b78a2106e57c55f02f36d (v2.5.0-rc0~28^2~2),
        #   but this should be handled properly because CPU featur properties
        #   were already available in QEMU 2.4.0
        #
        # the default:
        ('x86_64-cpu',            'abm',                        False),
        ('i386-cpu',              'abm',                        False),
        # these below override the default above:
        ('qemu64-x86_64-cpu',     'abm',                         True),
        ('qemu64-i386-cpu',       'abm',                         True),
        ('phenom-x86_64-cpu',     'abm',                         True),
        ('phenom-i386-cpu',       'abm',                         True),
        ('kvm64-x86_64-cpu',      'abm',                         True),
        ('kvm64-i386-cpu',        'abm',                         True),
        ('Opteron_G3-x86_64-cpu', 'abm',                         True),
        ('Opteron_G3-i386-cpu',   'abm',                         True),
        ('Opteron_G4-x86_64-cpu', 'abm',                         True),
        ('Opteron_G4-i386-cpu',   'abm',                         True),
        ('Opteron_G5-x86_64-cpu', 'abm',                         True),
        ('Opteron_G5-i386-cpu',   'abm',                         True),

        # * SSE4A was already enabled on qemu64, phenom, kvm64, Opteron_G3,
        #   Opteron_G4, and Opteron_G5 when we added CPU feature properties
        #   (commit 38e5c119c2925812bd441450ab9e5e00fc79e662 v2.4.0-rc0~101^2~1)
        # the default:
        ('x86_64-cpu',            'sse4a',                      False),
        ('i386-cpu',              'sse4a',                      False),
        # these below override the default above:
        ('qemu64-x86_64-cpu',     'sse4a',                       True),
        ('qemu64-i386-cpu',       'sse4a',                       True),
        ('phenom-x86_64-cpu',     'sse4a',                       True),
        ('phenom-i386-cpu',       'sse4a',                       True),
        ('kvm64-x86_64-cpu',      'sse4a',                       True),
        ('kvm64-i386-cpu',        'sse4a',                       True),
        ('Opteron_G3-x86_64-cpu', 'sse4a',                       True),
        ('Opteron_G3-i386-cpu',   'sse4a',                       True),
        ('Opteron_G4-x86_64-cpu', 'sse4a',                       True),
        ('Opteron_G4-i386-cpu',   'sse4a',                       True),
        ('Opteron_G5-x86_64-cpu', 'sse4a',                       True),
        ('Opteron_G5-i386-cpu',   'sse4a',                       True),

        # * POPCNT was already enabled on many CPU models when we added CPU feature
        #   properties (commit 38e5c119c2925812bd441450ab9e5e00fc79e662
        #   v2.4.0-rc0~101^2~1)
        #
        # the default:
        ('x86_64-cpu',                 'popcnt',                False),
        ('i386-cpu',                   'popcnt',                False),
        # these below override the default above:
        ("qemu64-x86_64-cpu",          "popcnt",                 True),
        ("qemu64-i386-cpu",            "popcnt",                 True),
        ("phenom-x86_64-cpu",          "popcnt",                 True),
        ("phenom-i386-cpu",            "popcnt",                 True),
        ("qemu32-x86_64-cpu",          "popcnt",                 True),
        ("qemu32-i386-cpu",            "popcnt",                 True),
        ("Nehalem-x86_64-cpu",         "popcnt",                 True),
        ("Nehalem-i386-cpu",           "popcnt",                 True),
        ("Westmere-x86_64-cpu",        "popcnt",                 True),
        ("Westmere-i386-cpu",          "popcnt",                 True),
        ("SandyBridge-x86_64-cpu",     "popcnt",                 True),
        ("SandyBridge-i386-cpu",       "popcnt",                 True),
        ("IvyBridge-x86_64-cpu",       "popcnt",                 True),
        ("IvyBridge-i386-cpu",         "popcnt",                 True),
        ("Haswell-noTSX-x86_64-cpu",   "popcnt",                 True),
        ("Haswell-noTSX-i386-cpu",     "popcnt",                 True),
        ("Haswell-x86_64-cpu",         "popcnt",                 True),
        ("Haswell-i386-cpu",           "popcnt",                 True),
        ("Broadwell-noTSX-x86_64-cpu", "popcnt",                 True),
        ("Broadwell-noTSX-i386-cpu",   "popcnt",                 True),
        ("Broadwell-x86_64-cpu",       "popcnt",                 True),
        ("Broadwell-i386-cpu",         "popcnt",                 True),
        ("Opteron_G3-x86_64-cpu",      "popcnt",                 True),
        ("Opteron_G3-i386-cpu",        "popcnt",                 True),
        ("Opteron_G4-x86_64-cpu",      "popcnt",                 True),
        ("Opteron_G4-i386-cpu",        "popcnt",                 True),
        ("Opteron_G5-x86_64-cpu",      "popcnt",                 True),
        ("Opteron_G5-i386-cpu",        "popcnt",                 True),


        # * RDTSCP was already enabled on many CPU models when we added CPU feature
        #   properties (commit 38e5c119c2925812bd441450ab9e5e00fc79e662
        #   v2.4.0-rc0~101^2~1)
        #
        # the default:
        ('x86_64-cpu',                 'rdtscp',              False),
        ('i386-cpu',                   'rdtscp',              False),
        # these below override the default above:
        ("phenom-x86_64-cpu",          "rdtscp",               True),
        ("SandyBridge-x86_64-cpu",     "rdtscp",               True),
        ("IvyBridge-x86_64-cpu",       "rdtscp",               True),
        ("Haswell-noTSX-x86_64-cpu",   "rdtscp",               True),
        ("Haswell-x86_64-cpu",         "rdtscp",               True),
        ("Broadwell-noTSX-x86_64-cpu", "rdtscp",               True),
        ("Broadwell-x86_64-cpu",       "rdtscp",               True),
        ("Opteron_G2-x86_64-cpu",      "rdtscp",               True),
        ("Opteron_G3-x86_64-cpu",      "rdtscp",               True),
        ("Opteron_G4-x86_64-cpu",      "rdtscp",               True),
        ("Opteron_G5-x86_64-cpu",      "rdtscp",               True),

        # these ones might be true or false, it depends on the CPU model, and
        # it would require copying everything from the CPU model table
        # 38e5c119c2925812bd441450ab9e5e00fc79e662^
        #('x86_64-cpu',           'sse4a',                         ???),
        #('i386-cpu',             'sse4a',                         ???),
        #('x86_64-cpu',           'abm',                           ???),
        #('i386-cpu',             'abm',                           ???),
        #('x86_64-cpu',           'popcnt',                        ???),
        #('i386-cpu',             'popcnt',                        ???),

        ('virtio-pci',           'x-pcie-pm-init',                False),
        ('virtio-pci',           'x-pcie-lnkctl-init',            False),
        ('virtio-pci',           'x-pcie-deverr-init',            False),
        ('virtio-pci',           'x-ignore-backend-features',      True),
        ('virtio-pci',           'x-disable-pcie',                 True),
        ('virtio-pci',           'virtio-pci-bus-master-bug-migration', True),
        ('virtio-pci',           'page-per-vq',                    True),
        ('virtio-pci',           'migrate-extra',                 False),
        ('virtio-pci',           'disable-modern',                 True),
        ('virtio-pci',           'disable-legacy',                False),
        # commit f58b39d2d5b6dea1a757e1dc7d67a44eac1c4f9c
        ('virtio-mmio',          'format_transport_address',      False),
        ('virtio-serial-device', 'emergency-write',               False),
        ('virtio-net-pci',       'guest_announce',                False),
        ('virtio-net-pci',       'ctrl_guest_offloads',           False),
        # note that "any_layout" is registered at virtio-device, but
        # alias properties are registered at virtio-pci subclasses.
        # the compat_props properties, on the other hand, are set
        # at the virtio-pci subclasses, so provide the omitted-proerty
        # value for virtio-pci too.
        ('virtio-device',        'any_layout',                    False),
        ('virtio-pci',           'any_layout',                    False),
        # commit a4c0d1deb785611c96a455f65ec032976b00b36f:
        ('fw_cfg',               'dma_enabled',                   False),
        ('fw_cfg_io',            'x-file-slots',                   0x10),
        ('fw_cfg_mem',           'x-file-slots',                   0x10),
        ('intel-iommu',          'x-buggy-eim',                    True),
        ('kvmclock',             'x-mach-use-reliable-get-clock', False),
        ('xio3130-downstream',   'power_controller_present',      False),
        ('ioh3420',              'power_controller_present',      False),
        ('vmxnet3',              'x-disable-pcie',                 True),
        # commit b22e0aef462df40e3355ee1cdf707b9578d23706:
        ('vmxnet3',              'x-old-msi-offsets',              True),
        ('VGA',                  'qemu-extended-regs',            False),
        ('usb-redir',            'streams',                       False),
        ('usb-mouse',            'usb_version',                       1),
        ('usb-kbd',              'usb_version',                       1),
        ('ICH9-LPC',             'memory-hotplug-support',        False),
        ('PIIX4_PM',             'memory-hotplug-support',        False),
        ('PIIX4_PM',             'acpi-pci-hotplug-with-bridge-support', False),
        ('pci-serial',           'prog_if',                           0),
        ('pci-serial-2x',        'prog_if',                           0),
        ('pci-serial-4x',        'prog_if',                           0),
        ('nec-usb-xhci',         'superspeed-ports-first',        False),
        ('nec-usb-xhci',         'force-pcie-endcap',              True),
        ('apic-common',          'legacy-instance-id',             True),
        ('apic-common',          'version',                        0x11),
        ('ioapic',               'version',                        0x11),
        ('isa-fdc',              'fallback',                      '144'),
        # we can't use intel-hda-generic here, because some QEMU versions
        # didn't have a common intel-hda-generic class
        ('intel-hda',            'old_msi_addr',                   True),
        ('ich9-intel-hda',       'old_msi_addr',                   True),
        ('e1000',                'mitigation',                    False),
        ('e1000-82540em',        'mitigation',                    False),
        ('e1000',                'extra_mac_registers',           False),
        ('e1000-82540em',        'extra_mac_registers',           False),
        ('pci-bridge',           'shpc',                           True),
        # commit 5e89dc01133f8f5e621f6b66b356c6f37d31dafb:
        ('i82559a',              'x-use-alt-device-id',           False),
        # commit 9fa99d2519cbf71f871e46871df12cb446dc1c3e:
        ('i440FX-pcihost',       'x-pci-hole64-fix',              False),
        ('q35-pcihost',          'x-pci-hole64-fix',              False),
        # commit f4924974c7c72560f68ab298ac25a525a28a2124:
        ('virtio-mouse-device',  'wheel-axis',                    False),
        ('virtio-tablet-device', 'wheel-axis',                    False),
        # commit 75ebec11afe49539f71cc1c494e3010f91c86adb:
        ('virtio-net-device',    'x-mtu-bypass-backend',          False),
        # commit bc277a52fbea1532d1adf30ba0edf15ab3dcdead:
        ('pcie-root-port',       'x-migrate-msix',                False),
        # commit 2f295167e0c429cec233aef7dc8e9fd6f90376df:
        ('mch',                  'extended-tseg-mbytes',              0),
        # commit dbaabb25f441264d9029dc53e84a156269ecd275:
        ('intel-iommu',          'pt',                            False),
        ('amd-iommu',            'pt',                            False),
        # commit b8bab8eb6934cbf6577a18a9c5657d7707379ac0:
        ('ICH9-LPC',             'x-smi-broadcast',               False),
        # commit 952970ba5651e8f6d1fec7de0366c63a79cadfdb:
        ('pvscsi',               'x-old-pci-configuration',        True),
        # commit d5da3ef2e24c29ddb92e11a54d705873acb905bf:
        ('pvscsi',               'x-disable-pcie',                 True),

        #XXX: this probably doesn't match the upstream QEMU behavior,
        #     but we probably will never compare machine-types containing
        #     those __redhat_* properties with upstream machine-types
        #     directly, anyway
        ('rtl8139',              '__redhat_send_rxokmul',         False),
        ('e1000e',               '__redhat_e1000e_7_3_intr_state', True),
        ('ICH9-LPC',             '__com.redhat_force-rev1-fadt',   True),
    ]

    r = {}
    apply_compat_props(binary, '<omitted-props>', r, (dict(driver=d, property=p, value=v) for (d, p, v) in OMITTED_PROP_VALUES))

    #XXX: this one can't be solved without looking at other information:
    # Between commit 39c88f56977f9ad2451444d70dd21d8189d74f99 (v2.8.0-rc0~137^2)
    # and 04e27c6bb034e57e60739362a90bc11a4d6f3ad4 (v2.8.0-rc2~5^2~2)
    # QEMU do _not_ have the property available, but it will
    # include the pcspk migration section in the migration stream.
    # This means we can't know which option we have, unless we check
    # the 'vmsd' field in the device class struct
    dt = binary.get_devtype('isa-pcspk')
    if dt and 'vmsd' in dt:
        # if vmsd value is known and vmsd was NULL, we know we're running a version that
        # didn't migrate pcspk data:
        migrate = (dt['vmsd'] is not None)
        apply_compat_props(binary, '<omitted-props>', r, [dict(driver='isa-pcspk', property='migrate', value=migrate)])

    # host-phys-bits is also tricky and depends on the binary version:
    # * Upstream, we never used the host address bits
    # * On RHEL >= 7.0, we always used the hsot address bits
    if binary.get_machine('pc-i440fx-rhel7.0.0'):
        host_phys_bits = True
    else:
        host_phys_bits = False
    apply_compat_props(binary, '<omitted-props>', r, [dict(driver='x86_64-cpu', property='host-phys-bits', value=host_phys_bits)])

    return r

def fixup_prop_value(ctx, compat, devtype, propname, v):
    # On some QEMU versions, the QInt conversion done by gdb-extract-qemu-info.py
    # reads level/xlevel as int32_t values instead of uint32_t:
    if devtype.endswith('-cpu') and propname in ['level', 'xlevel'] and v is not None:
        return int(v) & 0xFFFFFFFF
    if devtype.endswith('-cpu') and propname in ['min-level', 'min-xlevel'] and v is None:
        # if min-level/min-xlevel is not known, just use level/xlevel:
        lprop = propname.split('-')[1]
        return calculate_prop_value(ctx, compat, devtype, lprop)[1]
    if devtype in ['qemu64-x86_64-cpu', 'qemu32-x86_64-cpu', 'athlon-x86_64-cpu', \
                   'qemu64-i386-cpu', 'qemu32-i386-cpu', 'athlon-i386-cpu'] and \
       propname == 'model-id' and v == '':
        # workaround for gdb-extract-qemu-info.py limitation: x86_cpudef_setup()
        # called too late and won't run before we extract property info
        ver = ctx.binary1.qemu_version()
        if ver is None:
            return v
        return 'QEMU Virtual CPU version %s' % (ver)
    return v

def calculate_prop_value(ctx, compat, devtype, propname):
    """Try to find out what's going to be the default value for a property"""

    omitted1 = build_omitted_prop_dict(ctx.binary1)

    ctx.log(DEBUG, "calculating default value for %s.%s", devtype, propname)
    dt = ctx.binary1.get_devtype(devtype)
    dbg("dt: %s", dt and dt.get('type'))
    pi = get_devtype_property_info(dt, propname)
    dbg("pi: %s", pi)
    v = compat.get(devtype, {}).get(propname)
    dbg("v: %r", v)

    # we have a problem if:
    # 1) the property is set; 2) the devtype is really supported by the binary;
    # and 3) the propert is not present.
    # This means setting compat_props will fail if the device is present
    # on a VM.
    if pi is not None: # found property info
        v = parse_property_value(pi, v)
    elif v is not None and dt is not None:
        if devtype_has_full_prop_info(dt):
            ctx.report_result(ERROR, "Invalid property: %s.%s" % (devtype, propname))
        else:
            ctx.report_result(WARN, "Not enough info to validate property: %s.%s" % (devtype, propname))

    dbg("parsed v: %r", v)

    # if property was not on compat_props, try to get the default value from
    # device property info
    if v is None and pi is not None:
        v = pi.get('defval')

    dbg("defval v: %r", v)

    # if we still don't know what was the default value because the property
    # is not known, lookup the omitted-properties dictionary
    if v is None and pi is None:
        v = omitted1.get(devtype, {}).get(propname)

    dbg("omitted v: %r", v)

    v = fixup_prop_value(ctx, compat, devtype, propname, v)
    dbg("after fixup: %r", v)

    if v is None and dt is not None:
        # warn about not knowing the actual default value only if the device type is
        # really supported by the machine-type
        ctx.report_result(WARN, "I don't know the default value of %s.%s" % (devtype, propname))

    return pi, v


def compare_machine_compat_props(args, ctx, m1, m2):
    b1 = ctx.binary1
    b2 = ctx.binary2
    machinename = ctx.machinename
    compat1 = {}
    compat2 = {}
    apply_compat_props(b1, machinename, compat1, m1.get('compat_props', []))
    apply_compat_props(b2, machinename, compat2, m2.get('compat_props', []))

    if args.devices:
        devices_to_check = set(args.devices)
    else:
        devices_to_check = set(compat1.keys() + compat2.keys())
    if args.all_devices:
        devices_to_check.update(b1.all_devtypes())
        devices_to_check.update(b2.all_devtypes())

    for d in devices_to_check:
        #TODO: add option to compare all properties, not just the ones on compat_checker
        for p in set(compat1.get(d, {}).keys() + compat2.get(d, {}).keys()):
            pi1, v1 = calculate_prop_value(ctx.b1_ctx(), compat1, d, p)
            pi2, v2 = calculate_prop_value(ctx.b2_ctx(), compat2, d, p)

            if v1 is None or v2 is None:
                # we can't compare something we don't know about
                pass
            elif not compare_properties(pi1, v1, pi2, v2):
                ctx.report_result(ERROR, "difference at %s.%s (%r != %r)" % (d, p, v1, v2))
            else:
                ctx.report_result(DEBUG, "%s.%s is OK: %r == %r" % (d, p, v1, v2))


# we can't use None to indicate unknown value, because we can
# really have fields set to NULL
UNKNOWN_VALUE = object()

def get_omitted_machine_field(m, field):
    """Returns what value should be present in a MachineClass struct field
    to emulate QEMU's behavior when the field didn't exist yet
    """
    OMITTED_MACHINE_FIELDS = {
        'minimum_page_bits': 0,
        'numa_mem_align_shift': 23,
        'default_ram_size': 128 * 1024*1024,
        'auto_enable_numa_with_memhp': False,

        # default_boot_order and boot_order are equivalent:
        'default_boot_order': m.get('boot_order', UNKNOWN_VALUE),
        'boot_order': m.get('default_boot_order', UNKNOWN_VALUE),

        'units_per_default_bus': 0,
        'has_dynamic_sysbus': 0,
        'default_display': None,
        'pci_allow_0_address': 0,
        'legacy_fw_cfg_order': 1,

        'min_cpus': 0,
        'max_cpus': 0,
        'default_cpus': 0,

        'ignore_memory_transaction_failures': False,
        'valid_cpu_types': None,
    }

    return OMITTED_MACHINE_FIELDS.get(field, UNKNOWN_VALUE)

def parse_opts(s):
    if ',,' in s:
        raise Exception("I don't know how to parse escaped commas on QemuOpts")
    return dict(v.split('=', 1) for v in s.split(','))

def fixup_machine_field(ctx, m, field, v):
    """Fixup some machine fields when the info we have might be wrong or generate false positives"""

    mname = m.get('name', '')
    if mname == 'none' and \
         re.match('(|default_)boot_order|default_ram_size|block_default_type', field):
        # those fields don't matter for -machine none at all
        return None
    elif field == 'default_display' and v is None:
        # default_display=NULL and default_display="cirrus" are (supposed to be) equivalent
        return 'cirrus'
    elif field == 'min_cpus' and v == 0:
        # min_cpus == 0 is the same as min_cpus == 1
        return 1
    elif field == 'max_cpus' and v == 0:
        # max_cpus == 0 is the same as max_cpus == 1
        return 1
    elif field == 'default_cpus' and v == 0:
        # default_cpus == 0 is the same as default_cpus == 1
        return 1
    elif field == 'default_cpu_type' and v is UNKNOWN_VALUE and re.match('pc-.*|rhel[67]\..*', mname):
        for t in ['qemu64-x86_64-cpu', 'qemu64-i386-cpu']:
            if ctx.binary1.get_devtype(t):
                return t
        return v
    elif field == 'default_machine_opts':
        # assume firmware=bios.bin to be present if omitted:
        r = {'firmware':'bios.bin'}
        if v is not None:
            r.update(parse_opts(v))
        return r
    elif field == 'hw_version' and v is None:
        dbg('trying to find out actual hw_version for %s', ctx)
        # hw_version=NULL has a different result depending on QEMU version:
        qemu_ver = ctx.binary1.qemu_version()
        dbg("qemu version: %r", qemu_ver)
        if qemu_ver is None:
            return v
        ver_numbers = map(int, qemu_ver.split('.')) # '2.3.0' -> [2, 3, 0]
        if ver_numbers[:2] > [2, 4]:
            dbg('%r > [2, 4]', ver_numbers[:2])
            v = '2.5+'
        else:
            v = qemu_ver
        return v
    return v

def compare_machine_simple_fields(args, ctx, m1, m2):
    b1 = ctx.binary1
    b2 = ctx.binary2
    machinename = ctx.machinename

    # our comparison functions:
    def simple_compare(v1, v2):
        if v1 is UNKNOWN_VALUE:
            ctx.report_result(WARN, "%s: I don't know how to deal with missing machine.%s field" % (b1, f))
            return
        if v2 is UNKNOWN_VALUE:
            ctx.report_result(WARN, "%s: I don't know how to deal with missing machine.%s field" % (b2, f))
            return
        return v1 == v2

    def ensure_v2_ge(v1, v2):
        """Ensure v2 is greater or equal to v1.  Useful when a property representes a limit, not a ABI-visible value"""
        if v1 is UNKNOWN_VALUE:
            ctx.report_result(WARN, "%s: I don't know how to deal with missing machine.%s field" % (b1, f))
            return
        if v2 is UNKNOWN_VALUE:
            ctx.report_result(WARN, "%s: I don't know how to deal with missing machine.%s field" % (b2, f))
            return
        return v2 >= v1


    def ignore_unknown_value(v1, v2):
        """Compare values, but don't print a warning if we don't know one of them"""
        return (v1 is UNKNOWN_VALUE) or (v2 is UNKNOWN_VALUE) or (v1 == v2)

    def compare_func_name(v1, v2):
        func_re = re.compile('<([^>]*)>')
        fname1 = v1 and func_re.search(v1).group(1)
        fname2 = v2 and func_re.search(v2).group(1)
        return fname1 == fname2

    def compare_nullness(v1, v2):
        """Just check if both values are NULL or non-NULL"""
        return (v1 is None) == (v2 is None)

    fields = set(m1.keys() + m2.keys())

    KNOWN_FIELDS = {
        # compat_props is checked separately by compare_machine_compat_props()
        'compat_props': None,

        # there's no easy way to support these fields on get_omitted_machine_field()
        # because when the MachineClass fields were introduced
        # (commit 71ae9e94d99240cd02926ad76fadb4963a873b09), some machine-types
        # set them to true and others set them to false
        'option_rom_has_mr': ignore_unknown_value,
        'rom_file_has_mr': ignore_unknown_value,

        # max_cpus doesn't need to match exactly: we just need it to be greater or equal
        'max_cpus': ensure_v2_ge,
        # has_dynamic_sybus can also change from 0 to 1, but not the other way around:
        'has_dynamic_sysbus': ensure_v2_ge,

        # things we skip and won't try to validate:

        #TODO: this script doesn't know yet how to compare hotpluggable-CPUs
        # data between different QEMU versions
        'query_hotpluggable_cpus': None,
        'has_hotpluggable_cpus': None,
        #TODO: script doesn't know what to do with 'reset' function pointer, either:
        'reset': None,
        #TODO: other functions we don't know how to compare:
        'hot_add_cpu': None,
        'init': None,
        'get_hotplug_handler': None,
        'possible_cpu_arch_ids': None,
        'cpu_index_to_socket_id': None,
        'cpu_index_to_instance_props': None,
        'numa_auto_assign_ram': None,
        'kvm_type': None,
        'get_default_cpu_node_id': None,

        # alias/is_default won't affect the machine ABI:
        'alias': None, # ignore field
        'is_default': None,
        'family': None,

        # QOM stuff we can ignore:
        'parent_class': None,
        'next': None,
    }

    for f in fields:
        compare_func = KNOWN_FIELDS.get(f, simple_compare)
        if compare_func is None:
            continue

        if f in m1:
            v1 = m1[f]
        else:
            v1 = get_omitted_machine_field(m1, f)

        if f in m2:
            v2 = m2[f]
        else:
            v2 = get_omitted_machine_field(m2, f)

        v1 = fixup_machine_field(ctx.b1_ctx(), m1, f, v1)
        v2 = fixup_machine_field(ctx.b2_ctx(), m2, f, v2)

        dbg("will compare machine.%s: %r vs %r", f, v1, v2)
        r = compare_func(v1, v2)
        if r is None:
            continue
        elif r:
            ctx.report_result(DEBUG, 'machine.%s is OK' % (f))
        else:
            ctx.report_result(ERROR, "difference at machine.%s (%r != %r)" % (f, v1, v2))

def compare_machine(args, ctx):
    m1 = ctx.binary1.get_machine(ctx.machinename)
    m2 = ctx.binary2.get_machine(ctx.machinename)
    if m1 is None:
        logger.info("%s doesn't have info about machine %s" % (ctx.binary1, ctx.machinename))
        return
    if m2 is None:
        logger.info("%s doesn't have info about machine %s" % (ctx.binary2, ctx.machinename))
        return

    compare_machine_simple_fields(args, ctx, m1, m2)
    compare_machine_compat_props(args, ctx, m1, m2)

def machines_to_handle(args, ctx):
    if args.machines:
        return args.machines
    else:
        machines = set(ctx.binary1.available_machines())
        machines.intersection_update(ctx.binary2.available_machines())
        return machines

def compare_binaries(args, ctx):
    for m in machines_to_handle(args, ctx):
        mctx = copy.copy(ctx)
        mctx.machinename = m
        dbg("will compare machine: %s", mctx)
        compare_machine(args, mctx)

def print_machine(args, ctx):
    m1 = ctx.binary1.get_machine(ctx.machinename)
    if m1 is None:
        return
    logger.info('Info for %s:', ctx)
    logger.info('  compat_props:')
    for c in m1.get('compat_props', []):
        logger.info('  - %(driver)s.%(property)s=%(value)r', c)

def print_binary(args, ctx):
    for m in machines_to_handle(args, ctx):
        mctx = copy.copy(ctx)
        mctx.machinename = m
        print_machine(args, mctx)

def main():
    parser = argparse.ArgumentParser(
        description='Compare machine-type compatibility info between multiple QEMU binaries')
    parser.add_argument('--machine', '-M', metavar='MACHINE',
                        help='machine-type to verify',
                        action='append', default=[], dest='machines')
    parser.add_argument('--device', '-D', metavar='DEVTYPE',
                        action='append', default=[], dest='devices',
                        help="Query info about a device type")
    parser.add_argument('--all-devices', action='store_true',
                        help="Check properties for all device types")
    #parser.add_argument('--all-machines', action='store_true',
    #                    help="Verify all machine-types")
    parser.add_argument('-d', '--debug',
                        dest='loglevel', action='store_const', const=DEBUG,
                        default=INFO,
                        help="Enable debugging messages")
    parser.add_argument('-q', '--quiet',
                        dest='loglevel', action='store_const', const=WARN,
                        help="Disable INFO messages")
    parser.add_argument('-O', metavar='FILE', dest='dump_file',
                        help="Dump raw JSON data to FILE")

    parser.add_argument('--qemu', '-Q', metavar='QEMU',
                        dest='files',
                        action='append', type=lambda f: (f, BINARY),
                        help='QEMU binary to run')
    parser.add_argument('--raw-file', metavar='FILE',
                        dest='files',
                        action='append', type=lambda f: (f, JSON),
                        help="Load raw JSON data from FILE")
    parser.add_argument('auto_files', metavar='FILE', nargs='*',
                        help="QEMU binary or JSON dump file")

    args = parser.parse_args()

    logging.basicConfig(stream=sys.stdout, level=args.loglevel,
                        format='%(levelname)s: %(message)s')
    binaries = []
    if args.files:
        binaries.extend([QEMUBinaryInfo(f, t) for f,t in args.files])
    if args.auto_files:
        binaries.extend([QEMUBinaryInfo(f, AUTO) for f in args.auto_files])

    if not binaries:
        parser.error("At least one QEMU binary or JSON file needs to be provided")
        return 1

    if args.dump_file and len(binaries) != 1:
        parser.error("Dumping to a JSON file is supported only if a single QEMU binary is provided")
        return 1

    for b in binaries:
        logger.info("Loading data from %s", b)
        b.load_data(args)

    dbg("loaded data for all QEMU binaries")

    if args.dump_file:
        json.dump(binaries[0].raw_data, open(args.dump_file, 'w'), indent=2)

    for i,b1 in enumerate(binaries):
        #print_binary(args, ValidationContext(binary1=b1))
        for b2 in binaries[i+1:]:
            logger.info("Comparing %s and %s", b1, b2)
            ctx = ValidationContext(binary1=b1, binary2=b2)
            compare_binaries(args, ctx)

if __name__ == '__main__':
    sys.exit(main())
