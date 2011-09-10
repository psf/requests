# -*- coding: utf-8 -*-

"""
requests.config
~~~~~~~~~~~~~~~

This module provides the Requests settings feature set.

"""

class Settings(object):

    def __init__(self, **kwargs):
        super(Settings, self).__init__()

    def __getattribute__(self, key):
        return object.__getattribute__(self, key)


settings = Settings()

settings.base_headers = {'User-Agent': 'python-requests.org'}
settings.accept_gzip = True
settings.proxies = None
settings.verbose = None
settings.timeout = None
settings.max_redirects = 30
settings.decode_unicode = True

#: Use socket.setdefaulttimeout() as fallback?
settings.timeout_fallback = True
