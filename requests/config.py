# -*- coding: utf-8 -*-

"""
requests.config
~~~~~~~~~~~~~~~

This module provides the Requests settings feature set.

"""

# Time (in seconds) to allow the request to connect to
# the remote host before timing it out.

# timeout = None


class Settings(object):
    _singleton = {}
    __attrs__ = ('timeout',)

    def __init__(self, **kwargs):
        super(Settings, self).__init__()

        self.__dict__ = self._singleton

    def __getattribute__(self, key):
        if key in object.__getattribute__(self, '__attrs__'):
            try:
                return object.__getattribute__(self, key)
            except AttributeError:
                return None
        return object.__getattribute__(self, key)


    def __enter__(self):
        pass

    def __exit__(self, *args):

        self.__dict__.update(self.__cache.copy())
        del self.__cache


    def __call__(self, *args, **kwargs):
        r = self.__class__()
        r.__cache = self.__dict__.copy()
        self.__dict__.update(*args, **kwargs)

        return r


settings = Settings()