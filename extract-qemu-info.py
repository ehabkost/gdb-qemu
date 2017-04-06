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


# ----------------------------------------------------------
# Note that we don't know what's the Python version used
# by the available GDB version, so try to keep this script
# compatible with both Python 3 and Python 2.7.

import gdb
import sys
import argparse
import logging
import traceback
import json
import re

logger = logging.getLogger('dump-machine-info')
dbg = logger.debug


##########################
# Generic helper functions
##########################

def E(expr):
    """Shortcut to gdb.parse_and_eval()"""
    return gdb.parse_and_eval(expr)

def T(name):
    """Shortcuto to gdb.lookup_type()"""
    return gdb.lookup_type(name)

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
    return '"%s"' % (s)

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

def value_to_py(v):
    """Convert a single value to an equivalent Python value"""
    t = v.type.strip_typedefs()
    code = t.code
    #dbg("field %s, type: %s (code %s)", f.name, t, type_code_name(code))   w
    #if code == gdb.TYPE_CODE_PTR:
    #    dbg("target code: %s", type_code_name(t.target().code))
    if code == gdb.TYPE_CODE_INT:
        return int(v)
    elif code == gdb.TYPE_CODE_BOOL:
        return bool(v)
    elif code == gdb.TYPE_CODE_PTR and \
        int(v) == 0: # NULL pointer
        return None
    elif code == gdb.TYPE_CODE_PTR and \
         t.target().unqualified() == T('char'):
        return v.string()
    elif code == gdb.TYPE_CODE_PTR and \
         t.target().code == gdb.TYPE_CODE_FUNC:
         return str(v)
    elif code == gdb.TYPE_CODE_ENUM:
        return str(v)
    elif code == gdb.TYPE_CODE_STRUCT:
        return value_to_dict(v)
    else:
        raise ValueError("Unsupported value type: %s" % (t))

def value_to_dict(v):
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
    #dbg("address of value: %x", int(v.address))
    for f in v.type.fields():
        fv = v[f.name]
        try:
            #dbg("r[%r] = %r", f.name, rv)
            r[f.name] = value_to_py(fv)
        except ValueError:
            pass
    return r


##############################################
# Helper functions to translate data from QEMU
##############################################

def g_new0(t):
    return E('g_malloc0(%d)' % (t.sizeof)).cast(t.pointer())

def g_free(ptr):
    return E('g_free')(ptr)

def qtailq_foreach(head, field):
    var = head['tqh_first']
    while int(var) != 0:
        yield var
        var = var[field]['tqe_next']

def global_prop_info(gp):
    """Return dictionary with info about a GlobalProperty"""
    r = value_to_dict(gp)
    del r['next'] # no need to return the linked-list field
    return r

def compat_props_garray(v):
    """Return compat_props list based on a GArray field

    This handles the compat_props field for QEMU v2.7.0-rc0 and newer.
    (field was changed by commit bacc344c548ce165a0001276ece56ee4b0bddae3)
    """
    if int(v) == 0: # NULL pointer
        return []

    #dbg("garray: %s", v)
    g_array_get_element_size = E('g_array_get_element_size')
    elem_sz = g_array_get_element_size(v)
    #dbg("elem sz: %d", elem_sz)
    count = int(v['len'])
    #dbg("%d elements", count)
    gptype = T('GlobalProperty').pointer()
    data = v['data']
    for i in range(count):
        addr = data + i*elem_sz
        #dbg("addr for elem %d: %x", i, int(addr))
        gp = addr.cast(gptype.pointer()).dereference()
        yield global_prop_info(gp)

def compat_props_gp_array(cp):
    """Return compat_props list for GlobalProperty[] array

    This handles the compat_props field for QEMU older than v2.7.0-rc0
    (field was changed by commit bacc344c548ce165a0001276ece56ee4b0bddae3)
    """
    while int(cp) != 0 and int(cp['driver']) != 0:
        #dbg("cp addr: %x", int(cp))
        yield global_prop_info(cp)
        cp += 1

def compat_props(mi):
    """Return list of compat_props items"""
    cp = mi['compat_props']

    # currently we can only handle the GArray version of compat_props:
    #dbg("cp type: %s", cp.type)
    if cp.type == T('GArray').pointer():
        return list(compat_props_garray(cp))
    elif cp.type == T('GlobalProperty').pointer():
        return list(compat_props_gp_array(cp))
    else:
        raise Exception("unsupported compat_props type: %s" % (cp.type))

def prop_info(prop):
    """Return dictionary containing information for qdev Property struct"""
    r = value_to_dict(prop)
    r['info'] = value_to_dict(prop['info'])

    defval = prop['defval']
    if int(prop['qtype']) == int(E('QTYPE_QBOOL')):
        r['defval'] = bool(defval)
    elif int(prop['info']['enum_table']) != 0:
        r['defval'] = (prop['info']['enum_table'] + int(defval)).dereference().string()
    elif int(prop['qtype']) == int(E('QTYPE_QINT')):
        r['defval'] = int(defval)
    else: # default value won't have any effect
        del r['defval']
    return r

def dev_class_props(dc):
    """Return list of property information for a DeviceClass

    Includes properties from parent classes, too
    """
    prop = dc['props'];
    while int(prop) != 0 and int(prop['name']) != 0:
        yield prop_info(prop)
        prop += 1

    get_parent = E('object_class_get_parent')
    dynamic_cast = E('object_class_dynamic_cast')
    oc = dc.cast(T('ObjectClass').pointer())
    parent = get_parent(oc)
    devstr = E('"device"')
    parent = dynamic_cast(parent, devstr)
    if int(parent) != 0:
        parent_dc = parent.cast(T('DeviceClass').pointer())
        for p in dev_class_props(parent_dc):
            yield p

def qobject_value(qobj):
    """Convert QObject value to a Python value"""
    dbg("qobj: %r", value_to_dict(qobj))
    dbg("qobj type: %s (size: %d)" % (qobj.type, qobj.type.sizeof))
    #execute("x /%dxb 0x%x" % (qobj.type.sizeof, int(qobj)))
    #execute("p qstring_get_str(0x%x)" % (int(qobj)))
    qtype = qobj['type']
    if find_field(qtype, 'code'):
        qtype = qtype['code']
    if qtype == E('QTYPE_NONE'):
        return None
    elif qtype == E('QTYPE_QINT'):
        return int(E('qint_get_int')(qobj.cast(T('QInt').pointer())))
    elif qtype == E('QTYPE_QSTRING'):
        return E('qstring_get_str')(qobj.cast(T('QString').pointer())).string()
    elif qtype == E('QTYPE_QFLOAT'):
        return float('qfloat_get_float')(qobj.cast(T('QFloat').pointer()))
    elif qtype == E('QTYPE_QBOOL'):
        try:
            return bool(E('qbool_get_bool')(qobj.cast(T('QBool').pointer())))
        except:
            return bool(E('qbool_get_int')(qobj.cast(T('QBool').pointer())))
    elif qtype == E('QTYPE_QDICT'):
        raise Exception("can't handle %s qobject type" % (qtype))

def object_iter_props(obj):
    """Iterate over properties of a given Object*"""
    # hack to allocate a ObjectPropertyIterator struct:
    itertype = None
    try:
        itertype = T('ObjectPropertyIterator')
    except KeyboardInterrupt:
        raise
    except:
        pass

    if itertype:
        iterptr = g_new0(itertype)
        try:
            E('object_property_iter_init')(iterptr, obj)
            while True:
                prop = E('object_property_iter_next')(iterptr)
                if int(prop) == 0:
                    break
                yield prop
        finally:
            g_free(iterptr)
    else:
        for p in qtailq_foreach(obj['properties'], 'node'):
            yield p

def object_class_instance_props(oc):
    """Try to query QOM properties available when actual instantiating an object"""
    if bool(E('object_class_is_abstract')(oc)):
        return

    # this operation is very risky: there are lots of devices that
    # don't expect to be created using object_new() and have their
    # properties queried without realizing the device first
    #
    # Some examples:
    # * getting the value of a child property triggers the obj->parent != NULL assertion
    #   at object_get_canonical_path_component() and I don't know why
    # * pc-dimm "size" property will crash if dimm->hostmem is not set

    obj = E('object_new')(E('object_class_get_name')(oc))
    try:
        for prop in object_iter_props(obj):
            p = value_to_dict(prop)
            if p['type'].startswith("child<"):
                # getting the value of a child property triggers the obj->parent != NULL assertion
                # at object_get_canonical_path_component() and I don't know why
                continue
            if int(prop['get']) == 0:
                # No getter function
                continue
            execute("set unwindonsignal on")
            errp = g_new0(T('Error').pointer())
            try:
                val = E('object_property_get_qobject')(obj, prop['name'], errp)
                if int(errp.dereference()) == 0:
                    p['value'] = qobject_value(val)
                else:
                    msg = E('error_get_pretty')(errp.dereference()).string()
                    logger.info("Error trying to get property %r from devtype %r: %s" % (p['name'], E('object_class_get_name')(oc).string(), msg))
            except KeyboardInterrupt:
                raise
            except:
                logger.warning("Exception trying to get property %r from devtype %r" % (p['name'], E('object_class_get_name')(oc).string()))
                logger.warning(traceback.format_exc())
            finally:
                execute("set unwindonsignal off")
                g_free(errp)
            yield p
    finally:
        E('object_unref')(obj)

########################
# Actual query functions
########################

def query_machine(machine):
    """Query raw information for a machine-type name"""
    mi = E('find_machine(%s)' % (c_string(machine)))
    if int(mi) == 0:
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

def query_device_type(devtype):
    """Query information for a specific device type name"""
    oc = E('object_class_by_name(%s)' % (c_string(devtype)))
    if int(oc) == 0:
        raise Exception("Can't find type %s" % (devtype))

    dc = oc.cast(T('DeviceClass').pointer())
    dbg("oc: 0x%x, dc: 0x%x", int(oc), int(dc))
    result = {}
    result.update(value_to_dict(dc))
    result['props'] = list(dev_class_props(dc))
    if not find_field(dc, 'cannot_destroy_with_object_finalize_yet') or \
        not bool(dc['cannot_destroy_with_object_finalize_yet']):
        result['instance_props'] = list(object_class_instance_props(oc))
    return result

# The functions that will handle each type of request
REQ_HANDLERS = {
    'machine': query_machine,
    'device-type': query_device_type,
}

def handle_request(reqtype, *args):
    handler = REQ_HANDLERS.get(reqtype)
    if handler is None:
        raise Exception("invalid request: %s" % (reqtype))
    return handler(*args)

def handle_requests(args):
    for req in args.requests:
        try:
            r = handle_request(*req)
            yield dict(request=req, result=r)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            if args.catch_exceptions:
                traceback.print_exc()
                command_loop()
            tb = traceback.format_exc()
            yield dict(request=req, exception=dict(type=str(type(e)), message=str(e)), traceback=tb)


###########
# MAIN CODE
###########

parser = argparse.ArgumentParser(prog='dump-machine-info.py',
                                 description='Dump raw machine-type info from a QEMU binary')
parser.add_argument('qemu_binary', metavar='QEMU',
                    help='QEMU binary to run')
parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                    help="Enable debugging messages")
parser.add_argument('--catch-exceptions', dest='catch_exceptions', action='store_true',
                    help="Catch exceptions and run gdb command loop")

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

args = parser.parse_args(args=sys.argv)

lvl = logging.INFO
if args.debug:
    lvl = logging.DEBUG
logging.basicConfig(stream=sys.stderr, level=lvl)

if not args.requests:
    parser.error("No action was requested")

# basic setup, to make GDB behave more predictably:
execute('set pagination off')

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

if fm.hit_count < 1:
    logger.error("Didn't hit the find_machine breakpoint :(")
    sys.exit(1)

# make sure it's safe to call find_machine() later:
fm.enabled = False

sys.stdout.write("[")
first = True
tracebacks = []
for r in handle_requests(args):
    if not first:
        sys.stdout.write(",")
    sys.stdout.write("\n  ")
    json.dump(r, sys.stdout)
    if r.get('traceback'):
        tracebacks.append(r)
    first = False
sys.stdout.write("\n]\n")

if tracebacks:
    for r in tracebacks:
        logger.info("Traceback for request %r:", r['request'])
        logger.info(r['traceback'])
    sys.exit(1)
