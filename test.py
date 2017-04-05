#!/usr/bin/env python3
#
# Simple test script for gdbrunner
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

import gdbrunner
#import gdbscript
import unittest
import unittest, subprocess, tempfile, os

# test error handling:

class GdbRunnerTest(unittest.TestCase):
    def setUp(self):
        self.gdb = gdbrunner.GDB()

    def tearDown(self):
        self.gdb.quit()

    def xtestExceptionHandling(self):
        with self.assertRaises(gdbrunner.GdbError):
            self.gdb.execute('file /non/existing/file')

    def xtestSimpleProcess(self):
        self.gdb.execute('file /bin/true')
        self.gdb.execute('run')

class DebuggingTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory('gdbrunner-test')
        program = r"""
        #include <stdio.h>
        static int myvar = 0;
        int main(int argc, char *argv[]) {
            printf("myvar: %d\n", myvar++);
            printf("myvar: %d\n", myvar++);
            printf("myvar: %d\n", myvar++);
            printf("myvar: %d\n", myvar++);
            return 0;
        }
        """
        c_file = os.path.join(self.tmpdir.name, 'test.c')
        self.bin_file = os.path.join(self.tmpdir.name, 'test')
        with open(c_file, 'w') as f:
            f.write(program)
        r = subprocess.check_call(['gcc', '-O0', '-ggdb', '-o', self.bin_file, c_file])
        self.gdb = gdbrunner.GDB()

    def tearDown(self):
        self.gdb.quit()
        self.tmpdir.cleanup()

    def testBreak(self):
        self.gdb.execute('file %s' % (self.bin_file))
        self.gdb.execute('break main')
        self.gdb.execute('run')
        self.gdb.execute('print myvar')
        self.gdb.execute('next')
        self.gdb.execute('print myvar')
        self.gdb.execute('next')
        self.gdb.execute('print myvar')
        self.gdb.execute('next')

if __name__ == '__main__':
    unittest.main()
