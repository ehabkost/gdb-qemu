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

def gdb_escape(s):
    invalid_chars = re.compile(r"""['"\\\s]""")
    if invalid_chars.search(s):
        raise Exception("Sorry, I don't know how to escape %r in a gdb command" % (s))
    return s

def c_string(s):
    # be very conservative, just in case:
    invalid_chars = re.compile(r'["\\\n]')
    if invalid_chars.search(s):
        raise Exception("Sorry, I don't know how to escape %r in a C string" % (s))
    return '"%s"' % (s)

def execute(*args, **kwargs):
    dbg('executing command: %r, %r', args, kwargs)
    r = gdb.execute(*args, to_string=True, **kwargs)
    dbg('command output: %s', r)

def type_code_name(code):
    """Find type code name, just for debugging"""
    for a in dir(gdb):
        if not a.startswith('TYPE_CODE_'):
            continue
        if code == getattr(gdb, a):
            return a
    return '%d' % (code)

def value_to_dict(v):
    """Return dictionary containing field values from GDB value @v"""
    r = {}
    dbg("value_to_dict(%r)", v)
    dbg("address of value: %x", int(v.address))
    for f in v.type.fields():
        fv = v[f.name]
        t = fv.type.strip_typedefs()
        code = t.code
        dbg("field %s, type: %s (code %s)", f.name, t, type_code_name(code))
        if code == gdb.TYPE_CODE_PTR:
            dbg("target code: %s", type_code_name(t.target().code))
        rv = None
        if code == gdb.TYPE_CODE_INT:
            rv = int(fv)
        elif code == gdb.TYPE_CODE_BOOL:
            rv = bool(fv)
        elif code == gdb.TYPE_CODE_PTR and \
            int(fv) == 0: # NULL pointer
            rv = None
        elif code == gdb.TYPE_CODE_PTR and \
             t.target().unqualified() == gdb.lookup_type('char'):
            rv = fv.string()
        elif code == gdb.TYPE_CODE_PTR and \
             t.target().code == gdb.TYPE_CODE_FUNC:

             rv = str(fv)
        else:
            continue

        dbg("r[%r] = %r", f.name, rv)
        r[f.name] = rv
    return r

def global_prop_info(gp):
    return dict(driver=gp['driver'].string(),
                property=gp['property'].string(),
                value=gp['value'].string())

def compat_props_garray(v):
    if int(v) == 0: # NULL pointer
        return []

    #dbg("garray: %s", v)
    g_array_get_element_size = gdb.parse_and_eval('g_array_get_element_size')
    elem_sz = g_array_get_element_size(v)
    #dbg("elem sz: %d", elem_sz)
    count = int(v['len'])
    #dbg("%d elements", count)
    gptype = gdb.lookup_type('GlobalProperty').pointer()
    data = v['data']
    for i in range(count):
        addr = data + i*elem_sz
        #dbg("addr for elem %d: %x", i, int(addr))
        gp = addr.cast(gptype.pointer()).dereference()
        yield global_prop_info(gp)

def compat_props_gp_array(cp):
    """Return compat_props list for GlobalProperty[] array"""
    while int(cp) != 0 and int(cp['driver']) != 0:
        dbg("cp addr: %x", int(cp))
        yield global_prop_info(cp)
        cp += 1

def compat_props(v):
    """Return list for items in compat_props"""
    cp = v['compat_props']

    # currently we can only handle the GArray version of compat_props:
    #dbg("cp type: %s", cp.type)
    if cp.type == gdb.lookup_type('GArray').pointer():
        return list(compat_props_garray(cp))
    elif cp.type == gdb.lookup_type('GlobalProperty').pointer():
        return list(compat_props_gp_array(cp))
    else:
        raise Exception("unsupported compat_props type: %s" % (cp.type))

def query_machine(machine):
    mi = gdb.parse_and_eval('find_machine(%s)' % (c_string(machine)))
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

def prop_info(prop):
    r = value_to_dict(prop.dereference())
    r['info'] = value_to_dict(prop['info'].dereference())

    defval = prop['defval']
    if int(prop['qtype']) == int(gdb.parse_and_eval('QTYPE_QBOOL')):
        r['defval'] = bool(defval)
    elif int(prop['info']['enum_table']) != 0:
        r['defval'] = (prop['info']['enum_table'] + int(defval)).dereference().string()
    elif int(prop['qtype']) == int(gdb.parse_and_eval('QTYPE_QINT')):
        r['defval'] = int(defval)
    else: # default value won't have any effect
        del r['defval']
    return r

def dev_class_props(dc):
    prop = dc['props'];
    while int(prop) != 0 and int(prop['name']) != 0:
        yield prop_info(prop)
        prop += 1

    get_parent = gdb.parse_and_eval('object_class_get_parent')
    dynamic_cast = gdb.parse_and_eval('object_class_dynamic_cast')
    oc = dc.cast(gdb.lookup_type('ObjectClass').pointer())
    parent = get_parent(oc)
    devstr = gdb.parse_and_eval('"device"')
    parent = dynamic_cast(parent, devstr)
    if int(parent) != 0:
        parent_dc = parent.cast(gdb.lookup_type('DeviceClass').pointer())
        for p in dev_class_props(parent_dc):
            yield p


def query_device_type(devtype):
    oc = gdb.parse_and_eval('object_class_by_name(%s)' % (c_string(devtype)))
    if int(oc) == 0:
        raise Exception("Can't find type %s" % (devtype))

    dc = oc.cast(gdb.lookup_type('DeviceClass').pointer())
    dbg("oc: 0x%x, dc: 0x%x", int(oc), int(dc))
    result = {}
    result.update(value_to_dict(dc.dereference()))
    result['props'] = list(dev_class_props(dc))
    return result

REQ_HANDLERS = {
    'query-machine': query_machine,
    'query-device-type': query_device_type,
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
        except Exception as e:
            tb = traceback.format_exc()
            yield dict(request=req, exception=dict(type=str(type(e)), message=str(e)), traceback=tb)

parser = argparse.ArgumentParser(prog='dump-machine-info.py',
                                 description='Dump raw machine-type info from a QEMU binary')
parser.add_argument('qemu_binary', metavar='QEMU',
                    help='QEMU binary to run')
parser.add_argument('--machine', '-M', metavar='MACHINE',
                    help='dump info for a machine-type',
                    action='append', type=lambda m: ('query-machine', m),
                    dest='requests', default=[])
parser.add_argument('--device', '-D', metavar='DEVTYPE',
                    help='dump info for a device type',
                    action='append', type=lambda d: ('query-device-type', d),
                    dest='requests')
parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                    help="Enable debugging messages"),
args = parser.parse_args(args=sys.argv)

lvl = logging.INFO
if args.debug:
    lvl = logging.DEBUG
logging.basicConfig(stream=sys.stderr, level=lvl)

dbg(gdb.__file__)

if not args.requests:
    parser.error("No action was requested")

# basic setup, to make GDB behave more predictably:
execute('set pagination off')

execute('file %s' % (gdb_escape(args.qemu_binary)))
execute('set args -S -machine none -nographic')
# find_machine() exists since the -M optino was added, so it
# is a safe place where we know the machine type tables are available
fm = gdb.Breakpoint('find_machine', internal=True)

# just to make sure we won't continue running QEMU if the find_machine
# breakpoint fails:
ml = gdb.Breakpoint('main_loop', internal=True)

execute('run')

if fm.hit_count < 1:
    logger.error("Didn't hit the find_machine breakpoint :(")
    sys.exit(1)

# make sure it's safe to call find_machine() later:
fm.enabled = False

json.dump(list(handle_requests(args)), sys.stdout)
