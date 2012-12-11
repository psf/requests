"""The function mimetools.choose_boundary() from Python 2.7, which seems to
have disappeared in Python 3 (although email.generator._make_boundary() might
work as a replacement?).

Tweaked to use lock from threading rather than thread.
"""
import os
from threading import Lock
_counter_lock = Lock()

_counter = 0
def _get_next_counter():
    global _counter
    with _counter_lock:
        _counter += 1
        return _counter

_prefix = None

def choose_boundary():
    """Return a string usable as a multipart boundary.

    The string chosen is unique within a single program run, and
    incorporates the user id (if available), process id (if available),
    and current time.  So it's very unlikely the returned string appears
    in message text, but there's no guarantee.

    The boundary contains dots so you have to quote it in the header."""

    global _prefix
    import time
    if _prefix is None:
        import socket
        try:
            hostid = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            hostid = '127.0.0.1'
        try:
            uid = repr(os.getuid())
        except AttributeError:
            uid = '1'
        try:
            pid = repr(os.getpid())
        except AttributeError:
            pid = '1'
        _prefix = hostid + '.' + uid + '.' + pid
    return "%s.%.3f.%d" % (_prefix, time.time(), _get_next_counter())
