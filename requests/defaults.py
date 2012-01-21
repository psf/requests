# -*- coding: utf-8 -*-

"""
requests.defaults
~~~~~~~~~~~~~~~~~

This module provides the Requests configuration defaults.

Configurations:

:base_headers: Default HTTP headers.
:verbose: Stream to write request logging to.
:max_redirects: Maximum number of redirects allowed within a request.s
:keep_alive: Reuse HTTP Connections?
:max_retries: The number of times a request should be retried in the event of a connection failure.
:danger_mode: If true, Requests will raise errors immediately.
:safe_mode: If true, Requests will catch all errors.
:pool_maxsize: The maximium size of an HTTP connection pool.
:pool_connections: The number of active HTTP connection pools to use.
"""

from . import __version__

defaults = dict()


defaults['base_headers'] = {
    'User-Agent': 'python-requests/%s' % __version__,
    'Accept-Encoding': ', '.join(('identity', 'deflate', 'compress', 'gzip')),
    'Accept': '*/*'
}

defaults['verbose'] = None
defaults['max_redirects'] = 30
defaults['pool_connections'] = 10
defaults['pool_maxsize'] = 10
defaults['max_retries'] = 0
defaults['danger_mode'] = False
defaults['safe_mode'] = False
defaults['keep_alive'] = True
