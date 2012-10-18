# -*- coding: utf-8 -*-

"""
requests.adapters
~~~~~~~~~~~~~~~~~

This module contains the transport adapters that Requests uses to define
and maintain connections.
"""

from .packages.urllib3.poolmanager import PoolManager

class BaseAdapter(object):
    """The Base Transport Adapter"""

    def __init__(self, config=None):
        super(BaseAdapter, self).__init__()
        self.config = config or {}
        self.session = None

    @property
    def configure(self, config):
        self.config.update(config)

    def send(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


class HTTPAdapter(BaseAdapter):
    """Built-In HTTP Adapter for Urllib3."""
    def __init__(self):
        super(HTTPAdapter, self).__init__()

        self.init_poolmanager()

    def init_poolmanager(self):
        self.poolmanager = PoolManager(
            num_pools=self.config.get('pool_connections'),
            maxsize=self.config.get('pool_maxsize')
        )

    def close(self):
        """Dispose of any internal state.

        Currently, this just closes the PoolManager, which closes pooled
        connections.
        """
        self.poolmanager.clear()

    def send(self, request):
        """Sends request object. Returns Response object."""
        pass



