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

def require_escaping(s):
    invalid_chars = re.compile('[\\\'\" \s]')
    if invalid_chars.search(s):
        return True

def execute(*args, **kwargs):
    dbg('executing command: %r, %r', args, kwargs)
    r = gdb.execute(*args, to_string=True, **kwargs)
    dbg('command output: %s', r)

def type_code_name(code):
    for a in dir(gdb):
        if not a.startswith('TYPE_CODE_'):
            continue
        if code == getattr(gdb, a):
            return a
    return '%d' % (code)

def value_to_dict(v):
    """Return dictionary containing field values from GDB value @v"""
    r = {}
    #dbg("value_to_dict(%r)", v)
    for f in v.type.fields():
        code = f.type.code
        #dbg("field %s, type code: %s", f.name, type_code_name(code))
        fv = v[f.name]
        rv = None
        if code == gdb.TYPE_CODE_INT:
            rv = int(fv)
        elif code == gdb.TYPE_CODE_BOOL:
            rv = bool(fv)
        else:
            try:
                rv = fv.string()
            except:
                pass

        if rv is not None:
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
    while int(cp['driver']) != 0:
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


parser = argparse.ArgumentParser(prog='dump-machine-info.py',
                                 description='Dump raw machine-type info from a QEMU binary')
parser.add_argument('qemu_binary', metavar='QEMU',
                    help='QEMU binary to run')
parser.add_argument('machine', metavar='MACHINE',
                    help='machine-type to dump')

args = parser.parse_args(args=sys.argv)

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

if require_escaping(args.qemu_binary):
    parser.error("Sorry, this QEMU binary name won't work")
if require_escaping(args.machine):
    parser.error("Sorry, this machine-type name won't work")

# basic setup, to make GDB behave more predictably:
execute('set pagination off')

execute('file %s' % (args.qemu_binary))
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

fm.enabled = False
mi = gdb.parse_and_eval('find_machine("%s")' % (args.machine))
if int(mi) == 0:
    logger.error("Can't find machine type %s", args.machine)
    sys.exit(1)

mi = mi.dereference()
dbg('mi: %s', mi)

dbg('mi type: %s', mi.type)
dbg("mi name: %s", mi['name'].string())
if mi['alias']:
    dbg("mi alias: %s", mi['alias'].string())

assert mi['name'].string() == args.machine or mi['alias'].string() == args.machine

result = {}
result.update(value_to_dict(mi))
result['compat_props'] = compat_props(mi)

print(json.dumps(result))
