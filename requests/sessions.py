# -*- coding: utf-8 -*-

"""
requests.session
~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
requests (cookies, auth, proxies).

"""

import requests.api
import cookielib

class Session(object):
    """A Requests session."""

    __attrs__ = ['headers', 'cookies', 'auth', 'timeout', 'proxies']


    def __init__(self, **kwargs):

        # Set up a CookieJar to be used by default
        self.cookies = cookielib.FileCookieJar()

        # Map args from kwargs to instance-local variables
        map(lambda k, v: (k in self.__attrs__) and setattr(self, k, v),
                kwargs.iterkeys(), kwargs.itervalues())

        # Map and wrap requests.api methods
        self._map_api_methods()


    def __repr__(self):
        return '<requests-client at 0x%x>' % (id(self))


    def _map_api_methods(self):
        """Reads each available method from requests.api and decorates
        them with a wrapper, which inserts any instance-local attributes
        (from __attrs__) that have been set, combining them with **kwargs.
        """

        def pass_args(func):
            def wrapper_func(*args, **kwargs):
                inst_attrs = dict((k, v) for k, v in self.__dict__.iteritems()
                        if k in self.__attrs__)
                # Combine instance-local values with kwargs values, with
                # priority to values in kwargs
                kwargs = dict(inst_attrs.items() + kwargs.items())
                return func(*args, **kwargs)
            return wrapper_func

        # Map and decorate each function available in requests.api
        map(lambda fn: setattr(self, fn, pass_args(getattr(requests.api, fn))),
                requests.api.__all__)


