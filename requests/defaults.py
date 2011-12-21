# -*- coding: utf-8 -*-

"""
requests.defaults
~~~~~~~~~~~~~~~~~

This module provides the Requests configuration defaults.

Configurations:

:base_headers: Default HTTP headers.
:verbose: Stream to write request logging to.
:timeout: Seconds until request timeout.
:max_redirects: Maximum number of redirects allowed within a request.
:decode_unicode: Decode unicode responses automatically?
:keep_alive: Reuse HTTP Connections?
:max_retries: The number of times a request should be retried in the event of a connection failure.
:safe_mode: If true, Requests will catch all errors.
:pool_maxsize: The maximium size of an HTTP connection pool.
:pool_connections: The number of active HTTP connection pools to use.

HTTPS configuration options:

:verify_cert: Whether to verify server SSL certificates (default: ``False``)
:ca_certs: A path to a concatenated certificate authority file. Required if
	``verify_cert`` is True.
:client_cert_file: Optional client-side certificate file.
:client_key_file: Optional client-side private key file.

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
defaults['decode_unicode'] = True
defaults['pool_connections'] = 10
defaults['pool_maxsize'] = 10
defaults['max_retries'] = 0
defaults['safe_mode'] = False
defaults['keep_alive'] = True
defaults['verify_cert'] = False
defaults['ca_certs'] = None
defaults['client_cert_file'] = None
defaults['client_key_file'] = None