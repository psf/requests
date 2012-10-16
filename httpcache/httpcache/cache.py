"""
The cache object API for implementing caches. The default is just a
dictionary, which in turns means it is not threadsafe for writing.
"""
import os
import re
import time

from contextlib import contextmanager
from threading import Lock
from cPickle import dump, load
from hashlib import md5


class BaseCache(object):

    def get(self, key):
        raise NotImplemented()

    def set(self, key, value):
        raise NotImplemented()

    def delete(self, key):
        raise NotImplemented()


class DictCache(BaseCache):

    def __init__(self, init_dict=None):
        self.data = init_dict or {}

    def get(self, key):
        return self.data.get(key, None)

    def set(self, key, value):
        self.data.update({key: value})

    def delete(self, key):
        if key in self.data:
            self.data.pop(key)


# Cache filename construction (original borrowed from Venus
# http://intertwingly.net/code/venus/)
re_url_scheme = re.compile(r'^\w+://')
re_slash = re.compile(r'[?/:|]+')


def safename(filename):
    """Return a filename suitable for the cache.

    Strips dangerous and common characters to create a filename we
    can use to store the cache in.
    """

    try:
        if re_url_scheme.match(filename):
            if isinstance(filename, str):
                filename = filename.decode('utf-8')
                filename = filename.encode('idna')
            else:
                filename = filename.encode('idna')
    except UnicodeError:
        pass
    if isinstance(filename, unicode):
        filename = filename.encode('utf-8')
    filemd5 = md5(filename).hexdigest()
    filename = re_url_scheme.sub("", filename)
    filename = re_slash.sub(",", filename)

    # limit length of filename
    if len(filename) > 200:
        filename = filename[:200]
    return ",".join((filename, filemd5))


@contextmanager
def filelock(key, mode, timeout=None, interval=.1):
    """
    A simple context manager that creates a temporary file for
    locking a specific cache entry.

    This was inspired pretty directly by:
      http://amix.dk/blog/post/19531
    """
    lockfile = '%s.lock' % key
    if timeout:
        iterations = int(timeout / interval)
    locked = os.path.exists(lockfile)
    while locked:
        error = FileCacheLockedException(lockfile, key)
        if timeout:
            # it is already locked, but we have a timeout if we
            # want to try and block until it is available
            time.sleep(interval)
            iterations -= 1
            locked = os.path.exists(lockfile)
            if not iterations:
                raise error
        else:
            # it is locked and we don't have a timeout, so raise
            # the error
            error

    with open(lockfile, 'w+') as file_lock:
        file_lock.write('1')
        with open(key, mode) as opened_file:
            yield opened_file
    os.remove(lockfile)


class FileCacheLockedException(Exception):

    def __init__(self, lockfile, fname):
        self.lockfile, self.fname = lockfile, fname
        msg = '"%s" is locked. Try removing "%s"' % (lockfile, fname)
        super(FileCacheLockedException, self).__init__(msg)


class FileCache(BaseCache):
    """
    A simple threadsafe file based cache.

    The file cache is a port of httplib2's directory cache. The only
    difference is that it uses a lock when writing the file and
    pickles the value. The pickling is used b/c we are using
    requests.Response objects.
    """

    def __init__(self, cache, worker=None):
        self.cache = cache
        self.safe = safename
        if not os.path.exists(cache):
            os.makedirs(self.cache)
        self.lock = Lock()

    def get(self, key):
        retval = None
        cache_full_path = os.path.join(self.cache, safename(key))
        try:
            with open(cache_full_path, "rb") as f:
                retval = load(f)
        except (IOError, EOFError):
            pass
        return retval

    def set(self, key, value):
        cache_full_path = os.path.join(self.cache, safename(key))
        with filelock(cache_full_path, "wb", timeout=1) as f:
            dump(value, f)

    def delete(self, key):
        cache_full_path = os.path.join(self.cache, safename(key))
        if os.path.exists(cache_full_path):
            os.remove(cache_full_path)
