# gdbrunner module
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
import os, subprocess, tempfile, time
from multiprocessing.managers import BaseManager

WAIT_TIME = 0.1
RETRIES = 100

MY_DIR = os.path.dirname(__file__)

class GdbError(RuntimeError):
    pass

class GdbManager(BaseManager):
    pass

class GDB(object):
    def __init__(self, start=True, stdout=None, stderr=None):
        self._process = None
        self._stdout = stdout
        self._stderr = stderr
        if start:
            self.start_gdb()

    def start_gdb(self):
        if self._process:
            return

        self._tmpdir = tempfile.TemporaryDirectory('gdbrunner-script')
        self._socketpath = os.path.join(self._tmpdir.name, 'socket')
        self._process = subprocess.Popen(
            ['gdb', '-P', os.path.join(MY_DIR, 'gdbscript.py')],
            stdout=self._stdout, stderr=self._stderr,
            env=dict(GDBSCRIPT_ADDRESS=self._socketpath))
        self._manager = GdbManager(address=self._socketpath, authkey=b'1234')
        self._manager.register('GdbModuleWrapper')
        self._manager.register('ServerController')
        for i in range(RETRIES):
            if os.path.exists(self._socketpath):
                break
            time.sleep(WAIT_TIME)
        self._manager.connect()
        self._gdb_module = self._manager.GdbModuleWrapper()

        self.gdb_setup()

    def gdb_setup(self):
        """Set up some GDB settings"""
        self.execute('set pagination off')

    def execute(self, *args, **kwargs):
        return self._gdb_module.execute(*args, **kwargs)

    def quit(self):
        if self._process:
            self._process.terminate()
            self._process.wait()
            r = self._process.returncode
            if r != 0:
                raise Exception("non-zero exit code of gdb: %r", self._process.returncode)
            self._process = None
            self._tmpdir.cleanup()

    def __del__(self):
        self.quit()


__all__ = ['GDB']
