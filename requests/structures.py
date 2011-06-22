# -*- coding: utf-8 -*-

"""
requests.structures
~~~~~~~~~~~~~~~~~~~

Datastructures that power Requests.

"""

class CaseInsensitiveDict(dict):
    """Case-insensitive Dictionary for :class:`Response <models.Response>` Headers.

    For example, ``headers['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header."""

    def _lower_keys(self):
        return map(str.lower, self.keys())


    def __contains__(self, key):
        return key.lower() in self._lower_keys()


    def __getitem__(self, key):
        # We allow fall-through here, so values default to None
        if key in self:
            return self.items()[self._lower_keys().index(key.lower())][1]
