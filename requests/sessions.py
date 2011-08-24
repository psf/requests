# -*- coding: utf-8 -*-

"""
requests.session
~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
requests (cookies, auth, proxies).

"""

import cookielib

from . import api
from .utils import add_dict_to_cookiejar



class Session(object):
    """A Requests session."""

    __attrs__ = ['headers', 'cookies', 'auth', 'timeout', 'proxies', 'hooks']


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

    def __enter__(self):
        return self

    def __exit__(self, *args):
        # print args
        pass


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

                # If a session request has a cookie_dict, inject the
                # values into the existing CookieJar instead.
                if isinstance(kwargs.get('cookies', None), dict):
                    kwargs['cookies'] = add_dict_to_cookiejar(
                        inst_attrs['cookies'], kwargs['cookies']
                    )

                if kwargs.get('headers', None) and inst_attrs.get('headers', None):
                    kwargs['headers'].update(inst_attrs['headers'])

                return func(*args, **kwargs)
            return wrapper_func

        # Map and decorate each function available in requests.api
        map(lambda fn: setattr(self, fn, pass_args(getattr(api, fn))),
                api.__all__)


def session(**kwargs):
    """Returns a :class:`Session` for context-managment."""

    return Session(**kwargs)