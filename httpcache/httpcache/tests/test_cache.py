"""
Tests for our caches
"""
import os

from threading import Thread
# from multiprocessing import Process
from httpcache.cache import FileCache, safename, filelock
from httpcache.cache import FileCacheLockedException


class RandomWriter(Thread):
    def __init__(self, cache):
        super(RandomWriter, self).__init__()
        self.key = 'threading_test'
        self.cache = cache

    def run(self):
        for x in range(0, 5):
            value = x * 1000
            self.cache.set(self.key, value)
            assert self.cache.get(self.key) == value


class TestFileCache(object):

    cache_dir = 'test_file_cache'

    def test_set_get_delete(self):
        fc = FileCache(self.cache_dir)
        fc.set('foo', 'bar')
        assert fc.get('foo') == 'bar'
        fc.delete('foo')
        assert fc.get('foo') == None

    def test_setting_with_multiple_threads(self):
        fc = FileCache(self.cache_dir)
        w1 = RandomWriter(fc)
        w2 = RandomWriter(fc)
        w1.start()
        w2.start()
        w1.join()
        w2.join()
        assert fc.get(w1.key) == 4000

    def test_locked_raises_exception(self):
        key, value = 'locked', {'foo': 'bar'}
        fc = FileCache(self.cache_dir)
        lockfile = os.path.join(self.cache_dir,
                                '%s.lock' % safename(key))
        with open(lockfile, 'w+') as lock:
            lock.write('1')
        assert os.path.exists(lockfile)
        try:
            fc.set(key, value)
            assert False
        except FileCacheLockedException:
            assert True
        os.remove(lockfile)
        fc.set(key, value)
        assert fc.get(key) == value
        assert not os.path.exists(lockfile)

    def test_filelock_timeout(self):
        fc = FileCache(self.cache_dir)
        fname = safename('locked')
        lockfile = '%s.lock' % fname
        with open(lockfile, 'w+') as lock:
            lock.write('1')
            try:
                with filelock(fname, 'w+', .5):
                    assert False
            except FileCacheLockedException:
                assert True
        os.remove(lockfile)
        assert not os.path.exists(lockfile)
