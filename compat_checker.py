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
import sys, argparse, logging, subprocess, json, os
import qmp

MYDIR = os.path.dirname(__file__)
GDB_EXTRACTOR = os.path.join(MYDIR, 'extract-qemu-info.py')

logger = logging.getLogger('compat-checker')

class QEMUBinaryInfo:
    def __init__(self, binary=None, datafile=None):
        self.binary = binary
        self.datafile = datafile

def run_gdb_extractor(binary, machines):
    args = ['gdb', '-q', '-P', GDB_EXTRACTOR]
    for m in machines:
        args.extend(['-M', m])
    args.append(binary)
    proc = subprocess.Popen(args, stdout=subprocess.PIPE)
    r = json.load(proc.stdout)
    proc.wait()
    return r

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
        if b.binary:
            b.raw_data = run_gdb_extractor(q, args.machine)
        else:
            b.raw_data = json.load(open(b.datafile))

    if args.dump_file:
        json.dump(binaries[0].raw_data, open(args.dump_file, 'w'), indent=2)

if __name__ == '__main__':
    sys.exit(main())
