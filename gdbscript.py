import gdb
from gdbrunner import GdbError
import traceback, os
from multiprocessing.connection import Client
from functools import wraps
import logging

logger = logging.getLogger('gdbscript')
dbg = logger.debug

def translate_exception(fn):
    """decorator that translates gdb exceptions to GdbError

    This is necessary because the multiprocessing module isn't able
    to pickle the gdb.error exception objects, as the 'gdb' module
    is not available on the other side.
    """
    @wraps(fn)
    def f(*args, **kwargs):
        try:
            dbg('will call: %r(*%r, **%r)', fn, args, kwargs)
            r = fn(*args, **kwargs)
            dbg('return value: %r', r)
            return r
        except gdb.error as e:
            dbg('exception: %r', e)
            raise GdbError(str(e))
        except Exception as e:
            dbg('exception2: %r', e)
            raise
    return f

class GDBScriptWrapper(object):
    """Wrapper around the 'gdb' module methods"""
    def __init__(self):
        self.running = True

    @translate_exception
    def execute(self, *args, **kwargs):
        return gdb.execute(*args, **kwargs)

    def quit(self):
        self.running = False

def run_client():
    """Single-thread server that will dispatch method calls to
    a GdbScriptWrapper object.

    We don't use Python's multiprocess.BaseManager because
    calling gdb methods from separate threads can make GDB crash.
    """
    addr = os.getenv('GDBSCRIPT_ADDRESS')
    if addr is None:
        raise Exception("GDBSCRIPT_ADDRESS not set")

    wrapper = GDBScriptWrapper()

    conn = Client(addr)
    while wrapper.running:
        request = conn.recv()
        method,args,kwargs = request
        fn = getattr(wrapper, method)
        r = None
        e = None
        tb = None
        try:
            r = fn(*args, **kwargs)
        except Exception as exc:
            e = exc
        conn.send( (r, e) )

try:
    run_client()
except SystemExit:
    # expected exception
    raise
except:
    traceback.print_exc()
    gdb.execute('quit')
