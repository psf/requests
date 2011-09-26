from ._collections import RecentlyUsedContainer
from .connectionpool import HTTPConnectionPool, HTTPSConnectionPool, get_host


pool_classes_by_scheme = {
    'http': HTTPConnectionPool,
    'https': HTTPSConnectionPool,
}

port_by_scheme = {
    'http': 80,
    'https': 433,
}


class PoolManager(object):
    """
    Allows for arbitrary requests while transparently keeping track of
    necessary connection pools for you.

    num_pools
        Number of connection pools to cache before discarding the least recently
        used pool.

    Additional parameters are used to create fresh ConnectionPool instances.

    """

    # TODO: Make sure there are no memory leaks here.

    def __init__(self, num_pools=10, **connection_pool_kw):
        self.connection_pool_kw = connection_pool_kw

        self.pools = RecentlyUsedContainer(num_pools)
        self.recently_used_pools = []

    def connection_from_host(self, host, port=80, scheme='http'):
        """
        Get a ConnectionPool based on the host, port, and scheme.
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
        Similar to connectionpool.connection_from_url but doesn't pass any
        additional keywords to the ConnectionPool constructor. Additional
        keywords are taken from the PoolManager constructor.
        """
        scheme, host, port = get_host(url)

        port = port or port_by_scheme.get(scheme, 80)

        return  self.connection_from_host(host, port=port, scheme=scheme)

    def urlopen(self, method, url, **kw):
        "Same as HTTP(S)ConnectionPool.urlopen, ``url`` must be absolute."
        conn = self.connection_from_url(url)
        return conn.urlopen(method, url, **kw)
