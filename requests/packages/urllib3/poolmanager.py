# urllib3/poolmanager.py
# Copyright 2008-2011 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php

from ._collections import RecentlyUsedContainer
from .connectionpool import (
    HTTPConnectionPool, HTTPSConnectionPool,
    get_host, connection_from_url,
)


__all__ = ['PoolManager', 'ProxyManager', 'proxy_from_url']


from .request import RequestMethods
from .connectionpool import HTTPConnectionPool, HTTPSConnectionPool


pool_classes_by_scheme = {
    'http': HTTPConnectionPool,
    'https': HTTPSConnectionPool,
}

port_by_scheme = {
    'http': 80,
    'https': 443,
}


class PoolManager(RequestMethods):
    """
    Allows for arbitrary requests while transparently keeping track of
    necessary connection pools for you.

    :param num_pools:
        Number of connection pools to cache before discarding the least recently
        used pool.

    :param \**connection_pool_kw:
        Additional parameters are used to create fresh
        :class:`urllib3.connectionpool.ConnectionPool` instances.

    Example: ::

        >>> manager = PoolManager()
        >>> r = manager.urlopen("http://google.com/")
        >>> r = manager.urlopen("http://google.com/mail")
        >>> r = manager.urlopen("http://yahoo.com/")
        >>> len(r.pools)
        2

    """

    # TODO: Make sure there are no memory leaks here.

    def __init__(self, num_pools=10, **connection_pool_kw):
        self.connection_pool_kw = connection_pool_kw
        self.pools = RecentlyUsedContainer(num_pools)

    def connection_from_host(self, host, port=80, scheme='http'):
        """
        Get a :class:`ConnectionPool` based on the host, port, and scheme.

        Note that an appropriate ``port`` value is required here to normalize
        connection pools in our container most effectively.
        """
        pool_key = (scheme, host, port)

        # If the scheme, host, or port doesn't match existing open connections,
        # open a new ConnectionPool.
        pool = self.pools.get(pool_key)
        if pool:
            return pool

        # Make a fresh ConnectionPool of the desired type
        pool_cls = pool_classes_by_scheme[scheme]
        pool = pool_cls(host, port, **self.connection_pool_kw)

        self.pools[pool_key] = pool

        return pool

    def connection_from_url(self, url):
        """
        Similar to :func:`urllib3.connectionpool.connection_from_url` but
        doesn't pass any additional parameters to the
        :class:`urllib3.connectionpool.ConnectionPool` constructor.

        Additional parameters are taken from the :class:`.PoolManager`
        constructor.
        """
        scheme, host, port = get_host(url)

        port = port or port_by_scheme.get(scheme, 80)

        return self.connection_from_host(host, port=port, scheme=scheme)

    def urlopen(self, method, url, **kw):
        """
        Same as :meth:`urllib3.connectionpool.HTTPConnectionPool.urlopen`.

        ``url`` must be absolute, such that an appropriate
        :class:`urllib3.connectionpool.ConnectionPool` can be chosen for it.
        """
        conn = self.connection_from_url(url)
        return conn.urlopen(method, url, assert_same_host=False, **kw)


class ProxyManager(RequestMethods):
    """
    Given a ConnectionPool to a proxy, the ProxyManager's ``urlopen`` method
    will make requests to any url through the defined proxy.
    """

    def __init__(self, proxy_pool):
        self.proxy_pool = proxy_pool

    def urlopen(self, method, url, **kw):
        "Same as HTTP(S)ConnectionPool.urlopen, ``url`` must be absolute."
        kw['assert_same_host'] = False
        return self.proxy_pool.urlopen(method, url, **kw)


def proxy_from_url(url, **pool_kw):
    proxy_pool = connection_from_url(url, **pool_kw)
    return ProxyManager(proxy_pool)
