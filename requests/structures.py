# -*- coding: utf-8 -*-
"""
requests.structures
~~~~~~~~~~~~~~~~~~~

Data structures that power Requests.
"""

import collections

from .basics import basestring, OrderedDict


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
        self._store = collections.OrderedDict()
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
            (lowerkey, keyval[1]) for (lowerkey, keyval) in self._store.items()
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


class HTTPHeaderDict(CaseInsensitiveDict):
    """A case-insensitive ``dict``-like object suitable for HTTP headers that
    supports multiple values with the same key, via the ``add``, ``extend``,
    ``multiget`` and ``multiset`` methods.
    """

    def __init__(self, data=None, **kwargs):
        super(HTTPHeaderDict, self).__init__()
        self.extend({} if data is None else data, **kwargs)

    #
    # We'll store tuples in the internal dictionary, but present them as a
    # concatenated string when we use item access methods.
    #

    def __setitem__(self, key, val):
        if not isinstance(val, basestring):
            raise ValueError('only string-type values are allowed')
        super(HTTPHeaderDict, self).__setitem__(key, (val,))

    def __getitem__(self, key):
        return ', '.join(super(HTTPHeaderDict, self).__getitem__(key))

    def lower_items(self):
        return (
            (lk, ', '.join(vals))
            for (lk, (k, vals))
            in self._store.items()
        )

    def copy(self):
        return type(self)(self)

    def getlist(self, key):
        """Returns a list of all the values for the named field. Returns an
        empty list if the key isn't present in the dictionary."""
        return list(self._store.get(key.lower(), (None, []))[1])

    def setlist(self, key, values):
        """Set a sequence of strings to the associated key - this will overwrite
        any previously stored value."""
        if not isinstance(values, (list, tuple)):
            raise ValueError('argument is not sequence')
        if any(not isinstance(v, basestring) for v in values):
            raise ValueError('non-string items in sequence')
        if not values:
            self.pop(key, None)
            return
        super(HTTPHeaderDict, self).__setitem__(key, tuple(values))

    def _extend(self, key, values):
        new_value_tpl = key, values

        # Inspired by urllib3's implementation - use one call which should be
        # suitable for the common case.
        old_value_tpl = self._store.setdefault(key.lower(), new_value_tpl)
        if old_value_tpl is not new_value_tpl:
            old_key, old_values = old_value_tpl
            self._store[key.lower()] = (old_key, old_values + values)

    def add(self, key, val):
        """Adds a key, value pair to this dictionary - if there is already a
        value for this key, then the value will be appended to those values.
        """
        if not isinstance(val, basestring):
            raise ValueError('value must be a string-type object')
        self._extend(key, (val,))

    def extend(self, *args, **kwargs):
        """Like update, but will add values to existing sequences rather than
        replacing them. You can pass a mapping object or a sequence of two
        tuples - values in these objects can be strings or sequence of strings.
        """
        if len(args) > 1:
            raise TypeError("extend() takes at most 1 positional "
                            "arguments ({0} given)".format(len(args)))

        for other in args + (kwargs,):
            if isinstance(other, collections.Mapping):

                # See if looks like a HTTPHeaderDict (either urllib3's
                # implementation or ours). If so, then we have to add values
                # in one go for each key.
                multiget = getattr(other, 'getlist', None)
                if multiget:
                    for key in other:
                        self._extend(key, tuple(multiget(key)))
                    continue

                # Otherwise, just walk over items to get them.
                item_seq = other.items()
            else:
                item_seq = other

            for ik, iv in item_seq:
                if isinstance(iv, basestring):
                    self._extend(ik, (iv,))
                elif any(not isinstance(v, basestring) for v in iv):
                    raise ValueError('non-string items in sequence')
                else:
                    self._extend(ik, tuple(iv))

    def __repr__(self):
        d = {}
        for k, vals in self._store.values():
            d[k] = vals[0] if len(vals) == 1 else vals
        return repr(d)


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

    def __iter__(self):
        return super(LookupDict, self).__dir__()

    def get(self, key, default=None):
        return self.__dict__.get(key, default)
