# -*- coding: utf-8 -*-

"""
requests.defaults
~~~~~~~~~~~~~~~~~

This module provides the Requests configuration defaults.

settings parameters:

- :base_headers: - Sets default User-Agent to `python-requests.org`
- :accept_gzip:  - Whether or not to accept gzip-compressed data
- :proxies: - http proxies?
- :verbose: - display verbose information?
- :timeout: - timeout time until request terminates
- :max_redirects: - maximum number of allowed redirects?
- :decode_unicode: - whether or not to accept unicode?

"""

from . import __version__

defaults = dict()


defaults['base_headers'] = {
    'User-Agent': 'python-requests/%s' % __version__,
    'Accept-Encoding': ', '.join(('identity', 'deflate', 'compress', 'gzip')),
    'Accept': '*/*'
}

defaults['proxies'] = {}
defaults['verbose'] = None
defaults['timeout'] = None
defaults['max_redirects'] = 30
defaults['decode_unicode'] = True
defaults['timeout_fallback'] = True
# defaults['keep_alive'] = True
# defaults['max_connections'] = 10