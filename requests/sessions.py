# -*- coding: utf-8 -*-

"""
requests.session
~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
requests (cookies, auth, proxies).

"""

import cookielib

from . import api
from ._config import get_config
from .utils import add_dict_to_cookiejar
from .packages.urllib3.poolmanager import PoolManager


def merge_kwargs(local_kwarg, default_kwarg):
    """Merges kwarg dictionaries.

    If a local key in the dictionary is set to None, it will be removed.
    """

    # Bypass if not a dictionary (e.g. timeout)
    if not hasattr(local_kwarg, 'items'):
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

    __attrs__ = [
        'headers', 'cookies', 'auth', 'timeout', 'proxies', 'hooks',
        'config'
    ]

    def __init__(self,
        headers=None,
        cookies=None,
        auth=None,
        timeout=None,
        proxies=None,
        hooks=None,
        config=None):

        self.headers = headers
        self.cookies = cookies
        self.auth = auth
        self.timeout = timeout
        self.proxies = proxies
        self.hooks = hooks
        self.config = get_config(config)

        self.__pools = PoolManager(
            num_pools=10,
            maxsize=1
        )

        # Map and wrap requests.api methods.
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

                # Merge local and session arguments.
                for attr in self.__attrs__:
                    default_attr = getattr(self, attr)
                    local_attr = kwargs.get(attr)

                    # Merge local and session dictionaries.
                    new_attr = merge_kwargs(local_attr, default_attr)

                    # Skip attributes that were set to None.
                    if new_attr is not None:
                        _kwargs[attr] = new_attr

                # Make sure we didn't miss anything.
                for (k, v) in kwargs.items():
                    if k not in _kwargs:
                        _kwargs[k] = v

                # Add in PoolManager, if neccesary.
                if self.config.get('keepalive'):
                    _kwargs['_pools'] = self.__pools

                # TODO: Persist cookies.

                return func(*args, **_kwargs)
            return wrapper_func

        # Map and decorate each function available in requests.api
        map(lambda fn: setattr(self, fn, pass_args(getattr(api, fn))), api.__all__)


def session(**kwargs):
    """Returns a :class:`Session` for context-managment."""

    return Session(**kwargs)
