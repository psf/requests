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



def merge_kwargs(local_kwarg, default_kwarg):
    """Merges kwarg dictionaries.

    If a local key in the dictionary is set to None, it will be removed.
    """

    if default_kwarg is None:
        return local_kwarg

    if local_kwarg is None:
        return default_kwarg

    # Bypass if not a dictionary (e.g. timeout)
    if not hasattr(default_kwarg, 'items'):
        return local_kwarg



    # Update new values.
    kwargs = default_kwarg.copy()
    kwargs.update(local_kwarg)

    # Remove keys that are set to None.
    for (k,v) in local_kwarg.items():
        if v is None:
            del kwargs[k]

    return kwargs


class Session(object):
    """A Requests session."""

    __attrs__ = ['headers', 'cookies', 'auth', 'timeout', 'proxies', 'hooks', 'params']


    def __init__(self,
        headers=None,
        cookies=None,
        auth=None,
        timeout=None,
        proxies=None,
        hooks=None,
        params=None):

        self.headers = headers or {}
        self.cookies = cookies or {}
        self.auth = auth
        self.timeout = timeout
        self.proxies = proxies or {}
        self.hooks = hooks or {}
        self.params = params or {}

        # Set up a CookieJar to be used by default
        self.cookies = cookielib.FileCookieJar()

        # Map and wrap requests.api methods
        self._map_api_methods()


    def __repr__(self):
        return '<requests-client at 0x%x>' % (id(self))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def _map_api_methods(self):
        """Reads each available method from requests.api and decorates
        them with a wrapper, which inserts any instance-local attributes
        (from __attrs__) that have been set, combining them with **kwargs.
        """

        def pass_args(func):
            def wrapper_func(*args, **kwargs):

                # Argument collector.
                _kwargs = {}

                # If a session request has a cookie_dict, inject the
                # values into the existing CookieJar instead.
                if isinstance(kwargs.get('cookies', None), dict):
                    kwargs['cookies'] = add_dict_to_cookiejar(
                        self.cookies, kwargs['cookies']
                    )

                for attr in self.__attrs__:
                # for attr in ['headers',]:
                    s_val = self.__dict__.get(attr)
                    r_val = kwargs.get(attr)

                    new_attr = merge_kwargs(r_val, s_val)

                    # Skip attributes that were set to None.
                    if new_attr is not None:
                        _kwargs[attr] = new_attr

                # Make sure we didn't miss anything.
                for (k, v) in kwargs.items():
                    if k not in _kwargs:
                        _kwargs[k] = v

                return func(*args, **_kwargs)

            return wrapper_func

        # Map and decorate each function available in requests.api
        map(lambda fn: setattr(self, fn, pass_args(getattr(api, fn))),
                api.__all__)


def session(**kwargs):
    """Returns a :class:`Session` for context-managment."""

    return Session(**kwargs)