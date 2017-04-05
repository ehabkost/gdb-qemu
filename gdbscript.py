import gdb
from gdbrunner import GdbManager, GdbError
import traceback, os
from multiprocessing.managers import BaseManager
from functools import wraps

def translate_exception(fn):
    """decorator that translates gdb exceptions to GdbError

    This is necessary because the multiprocessing module isn't able
    to pickle the gdb.error exception objects, as the 'gdb' module
    is not available on the other side.
    """
    @wraps(fn)
    def f(*args, **kwargs):
        try:
            print('will call: %r(*%r, **%r)' % (fn, args, kwargs))
            r = fn(*args, **kwargs)
            print('return value: %r' % (r))
            return r
        except gdb.error as e:
            print('exception: %r' % (e))
            raise GdbError(str(e))
        except:
            print('exception2: %r' % (e))
            raise
    return f

class GdbModuleWrapper(object):
    """Wrapper around the 'gdb' module methods"""
    @translate_exception
    def execute(self, *args, **kwargs):
        return gdb.execute(*args, **kwargs)

def run_server():
    addr = os.getenv('GDBSCRIPT_ADDRESS')
    if addr is None:
        raise Exception("GDBSCRIPT_ADDRESS not set")

    m = GdbManager(address=addr, authkey=b'1234')
    m.register('GdbModuleWrapper', callable=GdbModuleWrapper)
    s = m.get_server()
    s.serve_forever()

try:
    run_server()
except SystemExit:
    # expected exception
    raise
except:
    traceback.print_exc()
    gdb.execute('quit')
