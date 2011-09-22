# -*- coding: utf-8 -*-

"""
requests.config
~~~~~~~~~~~~~~~

This module provides the Requests settings feature set.

settings parameters:

TODO: Verify!!!
TODO: Make sure format is acceptabl/cool
- :base_headers: - Sets default User-Agent to `python-requests.org`
- :accept_gzip:  - Whether or not to accept gzip-compressed data
- :proxies: - http proxies?
- :verbose: - display verbose information?
- :timeout: - timeout time until request terminates
- :max_redirects: - maximum number of allowed redirects?
- :decode_unicode: - whether or not to accept unicode?

Used globally

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
