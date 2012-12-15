# -*- coding: utf-8 -*-

"""
requests.defaults
~~~~~~~~~~~~~~~~~

This module provides the Requests configuration defaults.

Configurations:

:base_headers: Default HTTP headers.
:max_redirects: Maximum number of redirects allowed within a request.s
:keep_alive: Reuse HTTP Connections?
:max_retries: The number of times a request should be retried in the event of a connection failure.
:pool_maxsize: The maximium size of an HTTP connection pool.
:pool_connections: The number of active HTTP connection pools to use.
:encode_uri: If true, URIs will automatically be percent-encoded.
:trust_env: If true, the surrouding environment will be trusted (environ, netrc).
"""

SCHEMAS = ['http', 'https']

from .utils import default_user_agent

defaults = dict()

defaults['base_headers'] = {
    'User-Agent': default_user_agent(),
    'Accept-Encoding': ', '.join(('gzip', 'deflate', 'compress')),
    'Accept': '*/*'
}

# Consumed at the session level, not connection.
defaults['max_redirects'] = 30
defaults['trust_env'] = True
# defaults['support_http0.9'] = True
