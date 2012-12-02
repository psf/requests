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
:strict_mode: If true, Requests will do its best to follow RFCs (e.g. POST redirects).
:pool_maxsize: The maximium size of an HTTP connection pool.
:pool_connections: The number of active HTTP connection pools to use.
:encode_uri: If true, URIs will automatically be percent-encoded.
:trust_env: If true, the surrouding environment will be trusted (environ, netrc).
:store_cookies: If false, the received cookies as part of the HTTP response would be ignored.

"""

SCHEMAS = ['http', 'https']

from .utils import default_user_agent

defaults = dict()

defaults['base_headers'] = {
    'User-Agent': default_user_agent(),
    'Accept-Encoding': ', '.join(('gzip', 'deflate', 'compress')),
    'Accept': '*/*'
}

defaults['verbose'] = None
defaults['max_redirects'] = 30
defaults['pool_connections'] = 10
defaults['pool_maxsize'] = 10
defaults['max_retries'] = 0
defaults['keep_alive'] = True
defaults['encode_uri'] = True
defaults['trust_env'] = True
defaults['store_cookies'] = True
defaults['support_http0.9'] = True
