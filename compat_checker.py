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
import qmp

MYDIR = os.path.dirname(__file__)
GDB_EXTRACTOR = os.path.join(MYDIR, 'extract-qemu-info.py')

logger = logging.getLogger('compat-checker')
dbg = logger.debug

def run_gdb_extractor(binary, machines):
    args = ['gdb', '-q', '-P', GDB_EXTRACTOR]
    for m in machines:
        args.extend(['-M', m])
    args.append(binary)
    proc = subprocess.Popen(args, stdout=subprocess.PIPE)
    r = json.load(proc.stdout)
    proc.wait()
    return r

class QEMUBinaryInfo:
    def __init__(self, binary=None, datafile=None):
        self.binary = binary
        self.datafile = datafile

    def get_stdout(self, *args):
        """Helper to simply run QEMU and get stdout output"""
        try:
            return subprocess.Popen([self.binary] + list(args),
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT).communicate()[0]
        except:
            return None

    def get_rpm_package(self):
        # use shell to ensure we will just get an error message if RPM
        # is not available
        return subprocess.Popen(['sh', '-c', "rpm -qf %s" % (self.binary)],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT).communicate()[0]

    def append_raw_item(self, reqtype, result, args=[]):
        self.raw_data.append(dict(request=[reqtype] + list(args), result=result))

    def extract_binary_data(self, args):
        self.raw_data = []
        self.append_raw_item('version', {'help': self.get_stdout('-version'),
                                         'rpm-qf': self.get_rpm_package()})
        self.append_raw_item('help', self.get_stdout('-help'))
        self.append_raw_item('device-help', self.get_stdout('-device', 'help'))
        self.append_raw_item('machine-help', self.get_stdout('-machine', 'help'))
        self.append_raw_item('cpu-help', self.get_stdout('-cpu', 'help'))
        self.append_raw_item('hostname', {'platform.node': platform.node(),
                                          'gethostname': socket.gethostname()})
        self.raw_data.extend(run_gdb_extractor(self.binary, args.machine))

    def load_data_file(self):
        self.raw_data = json.load(open(self.datafile))

    def load_data(self, args):
        if self.binary:
            self.extract_binary_data(args)
        else:
            self.load_data_file()

def main():
    parser = argparse.ArgumentParser(
        description='Compare machine-type compatibility info between multiple QEMU binaries')
    parser.add_argument('--qemu', '-Q', metavar='QEMU', required=True,
                        help='QEMU binary to run', action='append', default=[])
    parser.add_argument('--machine', '-M', metavar='MACHINE',
                        help='machine-type to verify', required=True,
                        action='append', default=[])
    parser.add_argument('--raw-file', metavar='FILE',
                        help="Load raw JSON data from FILE",
                        action='append', default=[])
    #parser.add_argument('--all-machines', action='store_true',
    #                    help="Verify all machine-types")
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        help="Enable debugging messages")
    parser.add_argument('-O', metavar='FILE', dest='dump_file',
                        help="Dump raw JSON data to FILE")

    args = parser.parse_args()

    lvl = logging.INFO
    if args.debug:
        lvl = logging.DEBUG
    logging.basicConfig(stream=sys.stderr, level=lvl)

    binaries = [QEMUBinaryInfo(q) for q in args.qemu]
    binaries.extend([QEMUBinaryInfo(datafile=f) for f in args.raw_file])

    if args.dump_file and len(binaries) != 1:
        parser.error("Dumping to a JSON file is supported only if a single QEMU binary is provided")
        return 1

    for b in binaries:
        b.load_data(args)

    dbg("loaded data for all QEMU binaries")

    if args.dump_file:
        json.dump(binaries[0].raw_data, open(args.dump_file, 'w'), indent=2)

if __name__ == '__main__':
    sys.exit(main())
