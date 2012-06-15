# -*- coding: utf-8 -*-

"""
requests.structures
~~~~~~~~~~~~~~~~~~~

Data structures that power Requests.

"""


class CaseInsensitiveDict(dict):
    """Case-insensitive Dictionary

    For example, ``headers['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header."""

    def __init__(self, data=None, **kwargs):
        if data is not None:
            self.update(data)
        if len(kwargs):
            self.update(**kwargs)

    @property
    def lower_keys(self):
        if not hasattr(self, '_lower_keys') or not self._lower_keys:
            self._lower_keys = dict((k.lower(), k) for k in list(self.keys()))
        return self._lower_keys

    def _clear_lower_keys(self):
        if hasattr(self, '_lower_keys'):
            self._lower_keys.clear()

    def __setitem__(self, key, value):
        dict.__setitem__(self, key.lower(), value)
        self._clear_lower_keys()

    def __delitem__(self, key):
        dict.__delitem__(self, self.lower_keys.get(key.lower(), key))
        self._lower_keys.clear()

    def __contains__(self, key):
        return key.lower() in self.lower_keys

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None
        if key in self:
            return dict.__getitem__(self, self.lower_keys[key.lower()])

    def get(self, key, default=None):
        if key in self:
            return self[key]
        else:
            return default

    def update(self, data=None, **kwargs):
        if data is not None and hasattr(data, 'items'):
            for key, value in data.items():
                self.__setitem__(key, value)

        if len(kwargs):
            for key, value in kwargs.items():
                self.__setitem__(key, value)

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
