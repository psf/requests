# -*- coding: utf-8 -*-

"""
requests.structures
~~~~~~~~~~~~~~~~~~~

Data structures that power Requests.
"""

import collections
import time

from .compat import OrderedDict

current_time = getattr(time, 'monotonic', time.time)


class CaseInsensitiveDict(collections.MutableMapping):
    """A case-insensitive ``dict``-like object.

    Implements all methods and operations of
    ``collections.MutableMapping`` as well as dict's ``copy``. Also
    provides ``lower_items``.

    All keys are expected to be strings. The structure remembers the
    case of the last key to be set, and ``iter(instance)``,
    ``keys()``, ``items()``, ``iterkeys()``, and ``iteritems()``
    will contain case-sensitive keys. However, querying and contains
    testing is case insensitive::

        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        cid['aCCEPT'] == 'application/json'  # True
        list(cid) == ['Accept']  # True

    For example, ``headers['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header, regardless
    of how the header name was originally stored.

    If the constructor, ``.update``, or equality comparison
    operations are given keys that have equal ``.lower()``s, the
    behavior is undefined.
    """

    def __init__(self, data=None, **kwargs):
        self._store = OrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key, value):
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key):
        return self._store[key.lower()][1]

    def __delitem__(self, key):
        del self._store[key.lower()]

    def __iter__(self):
        return (casedkey for casedkey, mappedvalue in self._store.values())

    def __len__(self):
        return len(self._store)

    def lower_items(self):
        """Like iteritems(), but with all lowercase keys."""
        return (
            (lowerkey, keyval[1])
            for (lowerkey, keyval)
            in self._store.items()
        )

    def __eq__(self, other):
        if isinstance(other, collections.Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    # Copy is required
    def copy(self):
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self):
        return str(dict(self.items()))


class LookupDict(dict):
    """Dictionary lookup object."""

    def __init__(self, name=None):
        self.name = name
        super(LookupDict, self).__init__()

    def __repr__(self):
        return '<lookup \'%s\'>' % (self.name)

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)


class TimedCacheManaged(object):
    """
    Wrap a function call in a timed cache
    """
    def __init__(self, fnc):
        self.fnc = fnc
        self.cache = TimedCache()

    def __call__(self, *args, **kwargs):
        key = args[0]
        found = None
        try:
            found = self.cache[key]
        except KeyError:
            found = self.fnc(key, **kwargs)
            self.cache[key] = found

        return found


class TimedCache(collections.MutableMapping):
    """
    Evicts entries after expiration_secs. If none are expired and maxlen is hit,
    will evict the oldest cached entry
    """
    def __init__(self, maxlen=32, expiration_secs=60):
        """
        :param maxlen: most number of entries to hold on to
        :param expiration_secs: the number of seconds to hold on
        to entries
        """
        self.maxlen = maxlen
        self.expiration_secs = expiration_secs
        self._dict = OrderedDict()

    def __repr__(self):
        return '<TimedCache maxlen:%d len:%d expiration_secs:%d>' % \
            (self.maxlen, len(self._dict), self.expiration_secs)

    def __iter__(self):
        return map(lambda kv: (kv[0], kv[1][1]), self._dict.items()).__iter__()

    def __delitem__(self, item):
        return self._dict.__delitem__(item)

    def __getitem__(self, key):
        """
        Look up an item in the cache. If the item
        has already expired, it will be invalidated and not returned

        :param key: which entry to look up
        :return: the value in the cache, or None
        """
        occurred, value = self._dict[key]
        now = int(current_time())

        if now - occurred > self.expiration_secs:
            del self._dict[key]
            raise KeyError
        else:
            return value

    def __setitem__(self, key, value):
        """
        Locates the value at lookup key, if cache is full, will evict the
        oldest entry

        :param key: the key to search the cache for
        :param value: the value to be added to the cache
        """
        now = int(current_time())

        while len(self._dict) >= self.maxlen:
            self._dict.popitem(last=False)

        return self._dict.__setitem__(key, (now, value))

    def __len__(self):
        """:return: the length of the cache"""
        return len(self._dict)

    def clear(self):
        """Clears the cache"""
        return self._dict.clear()
