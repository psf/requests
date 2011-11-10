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


#: Stream to log requests to.
defaults['verbose'] = None

#: Seconds until timeout.
defaults['timeout'] = None

#: Maximum number of redirects allowed within a request.
defaults['max_redirects'] = 30

#: Should Requests decode unicode?
defaults['decode_unicode'] = True

#: Reuse HTTP Connections?
defaults['keep_alive'] = True

#: The number of active HTTP connection pools to use at a time.
defaults['pool_connections'] = 10

#: The maximium size of an HTTP connection pool.
defaults['pool_maxsize'] = 1

#: The number of times a request should be retried in the event of a
#: connection failure.
defaults['max_retries'] = 0

#: If true, Requests will catch all errors.
defaults['safe_mode'] = False
