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
import unittest

# test error handling:

class GdbRunnerTest(unittest.TestCase):
    def setUp(self):
        self.gdb = gdbrunner.GDB()

    def tearDown(self):
        self.gdb.quit()

    def testExceptionHandling(self):
        gdb = gdbrunner.GDB()
        with self.assertRaises(gdbrunner.GdbError):
            self.gdb.execute('file /non/existing/file')

    def testSimpleProcess(self):
        self.gdb.execute('file /bin/true')
        self.gdb.execute('run')

if __name__ == '__main__':
    unittest.main()
