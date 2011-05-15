# -*- coding: utf-8 -*-

"""
requests.structures
~~~~~~~~~~~~~~~~~~~

Datastructures that power Requests.

"""

from UserDict import DictMixin


class CaseInsensitiveDict(DictMixin):
    """docstring for CaseInsensitiveDict"""

    def __init__(self, *args, **kwargs):
        # super(CaseInsensitiveDict, self).__init__()
        self.data = dict(*args, **kwargs)

    def __repr__(self):
        return self.data.__repr__()

    def __getstate__(self):
        return self.data.copy()

    def __setstate__(self, d):
        self.data = d

    def _lower_keys(self):
        return map(str.lower, self.data.keys())


    def __contains__(self, key):
        return key.lower() in self._lower_keys()


    def __getitem__(self, key):

        if key.lower() in self:
            return self.items()[self._lower_keys().index(key.lower())][1]


    def __setitem__(self, key, value):
        return self.data.__setitem__(key, value)


    def __delitem__(self, key):
        return self.data.__delitem__(key)


    def __keys__(self):
        return self.data.__keys__()


    def __iter__(self):
        return self.data.__iter__()


    def iteritems(self):
        return self.data.iteritems()
