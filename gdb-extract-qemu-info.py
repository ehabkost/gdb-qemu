#!/usr/bin/gdb -P
#
# GDB script to dump raw machine-type info from a QEMU binary
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

# Note about Python version:
# This script should work on both Python 3 and Python 2.7 interpreters.
# Unfortunately we don't have a choice, as it depends on the Python version
# against which GDB has been compiled.

import gdb
import sys
import argparse
import logging
import traceback
import json
import re

logger = logging.getLogger('dump-machine-info')
dbg = logger.debug


CATCH_EXCEPTIONS = False
UNSAFE_PROPS = set(['i440FX-pcihost.pci-hole64-end',
                    'i440FX-pcihost.pci-hole64-start',
                    'q35-pcihost.pci-hole64-end',
                    'q35-pcihost.pci-hole64-start',
                    'pc-dimm.size'])

##########################
# Generic helper functions
##########################

def E(expr):
    """Shortcut to gdb.parse_and_eval()"""
    return gdb.parse_and_eval(expr)

def T(name):
    """Shortcuto to gdb.lookup_type()"""
    return gdb.lookup_type(name)

AUTO_GLOBALS = [
  'error_get_pretty',
  'find_machine',
  'first_machine',
  'g_array_get_element_size',
  'g_free',
  'object_class_by_name',
  'object_class_dynamic_cast',
  'object_class_get_list',
  'object_class_get_name',
  'object_class_get_parent',
  'object_class_is_abstract',
  'object_new',
  'object_property_get_qobject',
  'object_property_iter_init',
  'object_property_iter_next',
  'object_property_iter_free',
  'object_unref',
  'qbool_get_bool',
  'qbool_get_int',
  'qint_get_int',
  'qstring_get_str',
  'QTYPE_NONE',
  'QTYPE_QBOOL',
  'QTYPE_QDICT',
  'QTYPE_QFLOAT',
  'QTYPE_QINT',
  'QTYPE_QSTRING',

  (E, 'devstr', '"device"'),

  # need this hack to make it work even if we don't have glib
  # debuginfo:
  (E, 'g_malloc0', '*(void *(*)(unsigned long))g_malloc0'),

  (T, 'char'),
  (T, 'DeviceClass'),
  (T, 'Error'),
  (T, 'GArray'),
  (T, 'GlobalProperty'),
  (T, 'long'),
  (T, 'ulong', 'unsigned long'),
  (T, 'MachineClass'),
  (T, 'ObjectClass'),
  (T, 'ObjectPropertyIterator'),
  (T, 'QBool'),
  (T, 'QFloat'),
  (T, 'QInt'),
  (T, 'QString'),
  (T, 'QEnumLookup'),
]

def register_auto_globals():
    for g in AUTO_GLOBALS:
        if type(g) is not tuple:
            g = (g,)

        if len(g) == 1:
            var = expr = g[0]
            parser = gdb.parse_and_eval
        elif len(g) == 2:
            parser,var = g
            expr = var
        elif len(g) == 3:
            parser,var,expr =g

        try:
            r = parser(expr)
        except KeyboardInterrupt:
            raise
        except:
            r = None
        globals()[var] = r

def command_loop():
    """Run a read/execute command-loop, for debugging"""
    prev = None
    while True:
        cmd = input("gdb> ")
        if not cmd:
            cmd = prev
        if cmd:
            try:
                gdb.execute(cmd, from_tty=True)
            except KeyboardInterrupt:
                raise
            except:
                traceback.print_exc()
                pass
            prev = cmd

def gdb_escape(s):
    """Escape string to use it on a gdb command"""
    invalid_chars = re.compile(r"""['"\\\s]""")
    if invalid_chars.search(s):
        raise Exception("Sorry, I don't know how to escape %r in a gdb command" % (s))
    return s

def c_string(s):
    """Return a C string literal sequence for a string"""
    # be very conservative, just in case:
    invalid_chars = re.compile(r'["\\\n]')
    if invalid_chars.search(s):
        raise Exception("Sorry, I don't know how to escape %r in a C string" % (s))
    return E('"%s"' % (s))

def execute(*args, **kwargs):
    """Just a debugging wrapper for gdb.execute()"""
    dbg('executing command: %r, %r', args, kwargs)
    r = gdb.execute(*args, to_string=True, **kwargs)
    dbg('command output: %s', r)

def type_code_name(code):
    """Find gdb type code name, just for debugging"""
    for a in dir(gdb):
        if not a.startswith('TYPE_CODE_'):
            continue
        if code == getattr(gdb, a):
            return a
    return '%d' % (code)


#############################################
# Helper functions to translate data from GDB
#############################################

def tolong(v):
    """Return value as long int"""
    return int(v.cast(long))

def toulong(v):
    """Return value as unsigned long int"""
    return int(v.cast(ulong))

def enumerate_fields(t):
    """Enumerate fields of a struct type, recursively

    Generates (bitpos, name, field) tuples.
    """
    t = t.strip_typedefs()
    assert t.code == gdb.TYPE_CODE_STRUCT
    for f in t.fields():
        yield (f.bitpos, f.name, f)
        if f.type and f.type.strip_typedefs().code == gdb.TYPE_CODE_STRUCT:
            for bitpos, name, sf in enumerate_fields(f.type.strip_typedefs()):
                yield (f.bitpos + bitpos, '%s.%s' % (f.name, sf.name), sf)

def find_field(t, fieldname):
    """Find a field on a value or type"""
    if type(t) == gdb.Value:
        t = t.type
    if t.code == gdb.TYPE_CODE_PTR:
        t = t.target()
    for f in t.fields():
        if f.name == fieldname:
            return f

def value_to_py(v, follow_pointer=False):
    """Convert a single value to an equivalent Python value

    If follow_pointer is not false, follow pointer values.
    follow_pointer can be a dictionary, in this case it will be
    used as the follow_pointers argument to value_to_dict().
    """
    t = v.type.strip_typedefs()
    code = t.code
    #dbg("field %s, type: %s (code %s)", f.name, t, type_code_name(code))   w
    #if code == gdb.TYPE_CODE_PTR:
    #    dbg("target code: %s", type_code_name(t.target().code))
    if code == gdb.TYPE_CODE_INT:
        return tolong(v)
    elif code == gdb.TYPE_CODE_BOOL:
        return bool(v)
    elif code == gdb.TYPE_CODE_PTR:
        target = t.target().strip_typedefs()
        if tolong(v) == 0: # NULL pointer
            return None
        elif target.unqualified() == char:
            return v.string()
        elif target.code == gdb.TYPE_CODE_FUNC:
            return str(v)
        elif follow_pointer:
            return value_to_py(v.dereference(), follow_pointer)
        else:
            dbg("not following pointer of target type: %s", type_code_name(target.code))
            # empty dictionary just to indicate it's not a NULL pointer
            return dict()
    elif code == gdb.TYPE_CODE_ENUM:
        return str(v)
    elif code == gdb.TYPE_CODE_STRUCT or code == gdb.TYPE_CODE_UNION:
        return value_to_dict(v, follow_pointer if type(follow_pointer) == dict \
                                else {})
    else:
        raise ValueError("Unsupported value type: %s" % (t))

def value_to_dict(v, follow_pointers={}):
    """Return dictionary containing field values from GDB value @v

    Try to include all the fields whose type we know how to translate
    to a JSON-compatible type.
    """
    r = {}
    # In case we have a pointer, dereference it automatically to
    # make this helper easier to use
    if v.type.code == gdb.TYPE_CODE_PTR:
        v = v.dereference()

    #dbg("value_to_dict(%r)", v)
    #dbg("address of value: %x", tolong(v.address))
    for f in v.type.fields():
        fv = v[f.name]
        try:
            dbg("r[%r] = value_to_py(%s)", f.name, fv)
            r[f.name] = value_to_py(fv, follow_pointers.get(f.name))
        except ValueError:
            pass
    return r


##############################################
# Helper functions to translate data from QEMU
##############################################


def g_new0(t):
    #dbg("g_malloc0 type: %s (%s)", g_malloc0.type, type_code_name(g_malloc0.type.code))
    #dbg("object_new type: %s", object_new.type)
    p = g_malloc0(t.sizeof).cast(t.pointer())
    return p


def qtailq_foreach(head, field):
    var = head['tqh_first']
    while tolong(var) != 0:
        yield var
        var = var[field]['tqe_next']

def global_prop_info(gp):
    """Return dictionary with info about a GlobalProperty"""
    r = value_to_dict(gp)
    if 'next' in r:
        del r['next'] # no need to return the linked-list field
    return r


def compat_props_garray(v):
    """Return compat_props list based on a GArray field

    This handles the compat_props field for QEMU v2.7.0-rc0 and newer.
    (field was changed by commit bacc344c548ce165a0001276ece56ee4b0bddae3)
    """
    if tolong(v) == 0: # NULL pointer
        return

    #dbg("garray: %s", v)
    elem_sz = g_array_get_element_size(v)
    #dbg("elem sz: %d", elem_sz)
    count = tolong(v['len'])
    #dbg("%d elements", count)
    gptype = GlobalProperty.pointer()
    data = v['data']
    for i in range(count):
        addr = data + i*elem_sz
        #dbg("addr for elem %d: %x", i, tolong(addr))
        gp = addr.cast(gptype.pointer()).dereference()
        yield global_prop_info(gp)

def compat_props_gp_array(cp):
    """Return compat_props list for GlobalProperty[] array

    This handles the compat_props field for QEMU older than v2.7.0-rc0
    (field was changed by commit bacc344c548ce165a0001276ece56ee4b0bddae3)
    """
    while tolong(cp) != 0 and tolong(cp['driver']) != 0:
        #dbg("cp addr: %x", tolong(cp))
        yield global_prop_info(cp)
        cp += 1

def compat_props(mi):
    """Return list of compat_props items"""
    cp = mi['compat_props']

    # currently we can only handle the GArray version of compat_props:
    #dbg("cp type: %s", cp.type)
    if cp.type == GArray.pointer():
        return list(compat_props_garray(cp))
    elif cp.type == GlobalProperty.pointer():
        return list(compat_props_gp_array(cp))
    else:
        raise Exception("unsupported compat_props type: %s" % (cp.type))

def enum_lookup(propinfo, val):
    tbl_type = propinfo['enum_table'].type.target().unqualified()
    if tbl_type == char.const().pointer():
        array = propinfo['enum_table']
    elif tbl_type == QEnumLookup:
        array = propinfo['enum_table']['array']
        if val > propinfo['enum_table']['size']:
            raise Exception("Invalid enum value %r (array size is %d)" % \
                            (val, propinfo['enum_table']['size']))
    else:
        raise Exception("I don't know how to do enum lookup for %s", propinfo)
    return (array + tolong(val)).dereference().string()

def prop_info(prop):
    """Return dictionary containing information for qdev Property struct"""
    r = value_to_dict(prop, follow_pointers={'info':True})

    # fixup defval according to property type:

    if find_field(prop, 'qtype'):
        # old interface: Property::qtype:
        defval = prop['defval']
        if tolong(prop['qtype']) == tolong(QTYPE_QBOOL):
            r['defval'] = bool(defval)
        elif tolong(prop['info']['enum_table']) != 0:
            r['defval'] = enum_lookup(prop['info'], defval)
        elif tolong(prop['qtype']) == tolong(QTYPE_QINT):
            r['defval'] = tolong(defval)
        else: # default value won't have any effect
            del r['defval']
    elif find_field(prop['info'], 'set_default_value'):
        # new interface: PropertyInfo::set_default_value:
        # implemented by commit a2740ad584839ac84f3cdb2d928de93a0d7f4e72
        fn = str(prop['info']['set_default_value'])
        defval = prop['defval']
        if defval.type.code == gdb.TYPE_CODE_UNION:
            defval = defval['i']

        if tolong(prop['info']['set_default_value']) == 0:
            del r['defval']
        elif '<set_default_value_enum>' in fn:
            r['defval'] = enum_lookup(prop['info'], defval)
        elif '<set_default_value_bool>' in fn:
            r['defval'] = bool(defval)
        elif '<set_default_value_int>' in fn:
            r['defval'] = tolong(defval)
        elif '<set_default_value_uint>' in fn:
            r['defval'] = toulong(defval)
        else:
            raise Exception("I don't know how to extract default value for property %r", r)
    else:
        raise Exception("I don't know how to extract default value for property %r", r)

    return r

def dev_class_props(dc):
    """Return list of property information for a DeviceClass

    Includes properties from parent classes, too
    """
    prop = dc['props'];
    while tolong(prop) != 0 and tolong(prop['name']) != 0:
        yield prop_info(prop)
        prop += 1

    oc = dc.cast(ObjectClass.pointer())
    parent = object_class_get_parent(oc)
    parent = object_class_dynamic_cast(parent, devstr)
    if tolong(parent) != 0:
        parent_dc = parent.cast(DeviceClass.pointer())
        for p in dev_class_props(parent_dc):
            yield p

def qobject_value(qobj):
    """Convert QObject value to a Python value"""
    #dbg("qobj: %r", value_to_dict(qobj))
    #dbg("qobj type: %s (size: %d)" % (qobj.type, qobj.type.sizeof))
    #execute("x /%dxb 0x%x" % (qobj.type.sizeof, tolong(qobj)))
    #execute("p qstring_get_str(0x%x)" % (tolong(qobj)))
    qtype = qobj['type']
    if find_field(qtype, 'code'):
        qtype = qtype['code']
    if qtype == QTYPE_NONE:
        return None
    elif qtype == QTYPE_QINT:
        return tolong(qint_get_int(qobj.cast(QInt.pointer())))
    elif qtype == QTYPE_QSTRING:
        return qstring_get_str(qobj.cast(QString.pointer())).string()
    elif qtype == QTYPE_QFLOAT:
        return float('qfloat_get_float')(qobj.cast(QFloat.pointer()))
    elif qtype == QTYPE_QBOOL:
        if qbool_get_bool:
            return bool(qbool_get_bool(qobj.cast(QBool.pointer())))
        else:
            return bool(qbool_get_int(qobj.cast(QBool.pointer())))
    elif qtype == QTYPE_QDICT:
        raise Exception("can't handle %s qobject type" % (qtype))

def object_iter_props(obj):
    """Iterate over properties of a given Object*"""
    # hack to allocate a ObjectPropertyIterator struct:
    if tolong(obj['properties']) == 0:
        return

    if ObjectPropertyIterator:
        dbg("iterinit: %s, type: %s", object_property_iter_init, object_property_iter_init.type)
        dbg("iterinit type dir: %r", dir(object_property_iter_init.type))

        # we might have 2 different object property iterator APIs:
        #init_args = len(object_property_iter_init.type.fields())
        #assert init_args in [1, 2]
        # unfortunately GDB 7.6.1-80.el7 doesn't support
        # type.fields() on functions, so we need to check the
        # string representation of the function type:
        dbg("obj: 0x%x", tolong(obj))
        if '(ObjectPropertyIterator *, Object *)' in str(object_property_iter_init.type):
            init_args = 2
        else:
            init_args = 1

        if init_args == 2:
            iterptr = g_new0(ObjectPropertyIterator)
            dbg("iterptr: 0x%x", tolong(iterptr))
            object_property_iter_init(iterptr, obj)
        else:
            iterptr = object_property_iter_init(obj)
        while True:
            dbg("iterptr: 0x%x\n", tolong(iterptr))
            prop = object_property_iter_next(iterptr)
            if tolong(prop) == 0:
                break
            yield prop
        if init_args == 1:
            object_property_iter_free(iterptr)
        else:
            g_free(iterptr)
    else:
        for p in qtailq_foreach(obj['properties'], 'node'):
            yield p

def object_prop_get_value(devtype, obj, prop, p):
    """Get property value from object, and set 'value' dictionary field

    If an exception or error occurrs, the 'value-exception' or 'value-error'
    fields will be set, instead.

    This operation is very risky: there are some devices that
    don't expect have their properties queried without being
    realized first. Some examples:
    * getting the value of a child property triggers the obj->parent != NULL assertion
      at object_get_canonical_path_component() and I don't know why
    * pc-dimm "size" property will crash if dimm->hostmem is not set
    """
    errp = g_new0(Error.pointer())
    try:
        val = object_property_get_qobject(obj, prop['name'], errp)
        if tolong(errp.dereference()) == 0:
            p['value'] = qobject_value(val)
        else:
            msg = error_get_pretty(errp.dereference()).string()
            logger.info("Error trying to get property %r from devtype %r: %s" % (p['name'], devtype, msg))
            p['value-error'] = msg
        g_free(errp)
    except KeyboardInterrupt:
        raise
    except:
        logger.warning("Exception trying to get property %r from devtype %r" % (p['name'], devtype))
        logger.warning(traceback.format_exc())
        p['value-exception'] = dict(traceback=traceback.format_exc())
        if CATCH_EXCEPTIONS:
            raise

def object_class_instance_props(devtype, oc):
    """Try to query QOM properties available when actual instantiating an object"""
    assert not bool(object_class_is_abstract(oc))

    obj = object_new(c_string(devtype))
    #dbg("obj: 0x%x: %s", tolong(obj), obj.dereference())
    for prop in object_iter_props(obj):
        p = value_to_dict(prop)
        if p['type'].startswith("child<"):
            # getting the value of a child property triggers the obj->parent != NULL assertion
            # at object_get_canonical_path_component() and I don't know why
            continue
        if tolong(prop['get']) == 0:
            # No getter function
            continue
        propkey = '%s.%s' % (devtype, prop['name'].string())
        if propkey in UNSAFE_PROPS:
            dbg("skipping unsafe property: %s", propkey)
        else:
            object_prop_get_value(devtype, obj, prop, p)

        yield p
    object_unref(obj)

def unwrap_machine(mc):
    if find_field(mc, 'qemu_machine'):
        return mc['qemu_machine']
    else:
        return mc

def get_machine(name):
    """Find machine class"""
    if find_machine:
        return find_machine(c_string(name))

    dbg("will look for machine manually:")

    # In case the QEMU binary has find_machine() inlined, we have
    # to look for the machine class/struct ourselves
    machines = object_class_get_list(c_string("machine"), 0)
    el = machines
    while tolong(el):
        mc = unwrap_machine(el['data'].cast(MachineClass.pointer()))
        #dbg("looking at mc: %s", mc)
        if mc['name'].string() == name or \
           tolong(mc['alias']) != 0 and mc['alias'].string() == name:
           return mc
        el = el['next']

    # if QOM lookup failed, look for the "first_machine" global,
    # for the linked list:
    try:
        m = first_machine
    except:
        m = None
    while m and tolong(m):
        if m['name'].string() == name or \
           tolong(m['alias']) != 0 and m['alias'].string() == name:
           return m
        m = m['next']

########################
# Actual query functions
########################

def query_machine(args, machine):
    """Query raw information for a machine-type name"""
    mi = get_machine(machine)
    if mi is None or tolong(mi) == 0:
        raise Exception("Can't find machine type %s" % (machine))

    mi = mi.dereference()
    dbg('mi: %s', mi)

    dbg('mi type: %s', mi.type)
    dbg("mi name: %s", mi['name'].string())
    if mi['alias']:
        dbg("mi alias: %s", mi['alias'].string())

    assert mi['name'].string() == machine or mi['alias'].string() == machine

    result = {}
    result.update(value_to_dict(mi))
    result['compat_props'] = compat_props(mi)
    return result

def query_device_type(args, devtype):
    """Query information for a specific device type name"""
    oc = object_class_by_name(c_string(devtype))
    if tolong(oc) == 0:
        raise Exception("Can't find type %s" % (devtype))

    dc = oc.cast(DeviceClass.pointer())
    #dbg("oc: 0x%x, dc: 0x%x", tolong(oc), tolong(dc))
    result = {}
    result.update(value_to_dict(dc, follow_pointers={'vmsd':True}))
    result['props'] = list(dev_class_props(dc))
    # note that we ignore cannot_destroy_with_object_finalize_yet, because
    # the risk is worth it: we can query all *-x86_64-cpu classes this way.
    # if we find other devices that crash, we can add them to UNSAFE_DEVS
    if args.instance_properties and devtype not in args.unsafe_devs \
       and not bool(object_class_is_abstract(oc)):
        result['instance_props'] = list(object_class_instance_props(devtype, oc))
    return result

# The functions that will handle each type of request
REQ_HANDLERS = {
    'machine': query_machine,
    'device-type': query_device_type,
}

def handle_request(args, reqtype, *reqargs):
    handler = REQ_HANDLERS.get(reqtype)
    if handler is None:
        raise Exception("invalid request: %s" % (reqtype))
    dbg("handling request: %r" % ((reqtype,) + reqargs, ))
    return handler(args, *reqargs)

def handle_requests(args):
    global CATCH_EXCEPTIONS
    if args.catch_exceptions:
        execute("set unwindonsignal off")
        CATCH_EXCEPTIONS = True
    else:
        execute("set unwindonsignal on")

    for req in args.requests:
        try:
            r = handle_request(args, *req)
            yield dict(request=req, result=r)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            if args.catch_exceptions:
                traceback.print_exc()
                command_loop()
            tb = traceback.format_exc()
            logger.debug("Traceback for request %r:", req)
            logger.debug(tb)
            yield dict(request=req, exception=dict(type=str(type(e)), message=str(e)), traceback=tb)


###########
# MAIN CODE
###########

def start_qemu(kill=False):
    if kill:
        execute('kill')

    execute('delete breakpoints')
    execute('file %s' % (gdb_escape(args.qemu_binary)))
    execute('set args -S -M will_never_run -nographic')
    
    # find_machine() exists since the -M optino was added, so it
    # is a safe place where we know the machine type tables are available
    fm = gdb.Breakpoint('find_machine', internal=True)
    fm.silent = True
    
    # just to make sure we won't continue running QEMU if the find_machine
    # breakpoint fails:
    ml = gdb.Breakpoint('main_loop', internal=True)
    ml.silent = True
    
    execute('run')
    
    dbg("ran!")

    if fm.hit_count < 1:
        raise Exception("Didn't hit the find_machine breakpoint. Is debuginfo available for the QEMU binary?")
    
    # make sure it's safe to call find_machine() later:
    fm.enabled = False

parser = argparse.ArgumentParser(prog='dump-machine-info.py',
                                 description='Dump raw machine-type info from a QEMU binary')
parser.add_argument('qemu_binary', metavar='QEMU',
                    help='QEMU binary to run')
parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                    help="Enable debugging messages")
parser.add_argument('--catch-exceptions', dest='catch_exceptions', action='store_true',
                    help="Catch exceptions and run gdb command loop")
parser.add_argument('--interactive-debug', action='store_true',
                    help="Run interactive debug prompt before any action")
parser.add_argument('--output-file', '-o', metavar='FILE',
                    help="Output JSON data to FILE")

# the --machine and --device options are kept on a single array, so we
# process in the same order they appeared:
parser.add_argument('--machine', '-M', metavar='MACHINE',
                    help='dump info for a machine-type',
                    action='append', type=lambda m: ('machine', m),
                    dest='requests', default=[])
parser.add_argument('--device', '-D', metavar='DEVTYPE',
                    help='dump info for a device type',
                    action='append', type=lambda d: ('device-type', d),
                    dest='requests')
parser.add_argument('--unsafe-device', metavar='DEVTYPE',
                    help="Don't try to get instance properties from DEVTYPE",
                    action='append', default=[], dest='unsafe_devs')
parser.add_argument('--no-instance-properties', action='store_false',
                    dest='instance_properties', default=True,
                    help="Don't query QOM instance properties directly")

args = parser.parse_args(args=sys.argv)

lvl = logging.INFO
if args.debug:
    lvl = logging.DEBUG
logging.basicConfig(stream=sys.stderr, level=lvl)

if not args.requests:
    parser.error("No action was requested")

# basic setup, to make GDB behave more predictably:
execute('set pagination off')

start_qemu()

register_auto_globals()

if args.interactive_debug:
    command_loop()

if args.output_file:
    out = open(args.output_file, 'w')
else:
    out = sys.stdout

out.write("[")
first = True
tracebacks = []
for r in handle_requests(args):
    if not first:
        out.write(",")
    out.write("\n  ")
    json.dump(r, out)
    if r.get('traceback'):
        tracebacks.append(r)
    first = False
out.write("\n]\n")

exit = 0
if tracebacks:
    for r in tracebacks:
        logger.info("Traceback for request %r:", r['request'])
        logger.info(r['traceback'])
    exit = 1

execute('kill')
sys.exit(exit)
