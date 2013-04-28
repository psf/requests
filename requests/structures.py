# -*- coding: utf-8 -*-

"""
requests.structures
~~~~~~~~~~~~~~~~~~~

Data structures that power Requests.

"""

import os
import collections
from itertools import islice, chain


class IteratorProxy(object):
    """docstring for IteratorProxy"""
    def __init__(self, i):
        self.i = i
        # self.i = chain.from_iterable(i)

    def __iter__(self):
        return self.i

    def __len__(self):
        if hasattr(self.i, '__len__'):
            return len(self.i)
        if hasattr(self.i, 'len'):
            return self.i.len
        if hasattr(self.i, 'fileno'):
            return os.fstat(self.i.fileno()).st_size

    def read(self, n):
        return "".join(islice(self.i, None, n))


class CaseInsensitiveDict(object):
    """
    A case-insensitive ``dict``-like object. Implements all methods
    and operations of ``collections.MutableMapping`` as well as
    ``copy``, ``iterkeys``, ``iteritems``, and ``itervalues``. All
    keys are expected to be strings, and are stored/returned in
    lowercase.

    For example, ``headers['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header.

    If the constructor or ``.update`` is given keys that have equal
    ``.lower()``s, it will raise ValueError as the behavior of such
    input cannot be defined sanely.

    """
    def __init__(self, data=None, **kwargs):
        self._store = dict()
        if data is None:
            self.update({}, **kwargs)
        else:
            self.update(data, **kwargs)

    def __setitem__(self, key, value):
        self._store[key.lower()] = value

    def __getitem__(self, key):
        return self._store[key.lower()]

    def __delitem__(self, key):
        del self._store[key.lower()]

    def __iter__(self):
        return iter(self._store)

    def __len__(self):
        return len(self._store)

    def __contains__(self, key):
        return key.lower() in self._store

    def keys(self):
        return self._store.keys()

    def items(self):
        return self._store.items()

    def values(self):
        return self._store.values()

    def get(self, key, default=None):
        return self._store.get(key.lower(), default)

    def __eq__(self, other):
        if isinstance(other, CaseInsensitiveDict):
            return self._store == other._store
        else:
            raise TypeError(
                "Can only compare with CaseInsensitiveDict instances"
            )

    def __ne__(self, other):
        return not (self == other)

    def pop(self, key, default=None):
        if default is None:
            return self._store.pop(key.lower())
        else:
            return self._store.pop(key.lower(), default)

    def popitem(self):
        return self._store.popitem()

    def clear(self):
        self._store.clear()

    def update(self, other, **kwargs):
        if isinstance(other, collections.Mapping):
            items = other.items()
            self._store = dict((k.lower(), v) for (k, v) in other.items())
        else:
            items = other
            self._store = dict((i[0].lower(), i[1]) for i in other)
        seenkeys = set()
        for key, value in chain(items, kwargs.items()):
            key = key.lower()
            if key in seenkeys:
                raise ValueError(
                    'Keys must be unique after being lowercased, found "%s" '
                    'at least twice.'
                )
            self._store[key] = value
            seenkeys.add(key)

    def setdefault(self, key, default=None):
        return self._store.setdefault(key.lower(), default)

    # Remaining methods not strictly needed for collections.Mapping
    def copy(self):
        return CaseInsensitiveDict(self._store.copy())

    def iteritems(self):
        return self._store.iteritems()

    def iterkeys(self):
        return self._store.iterkeys()

    def itervalues(self):
        return self._store.itervalues()

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self._store)

collections.MutableMapping.register(CaseInsensitiveDict)


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
