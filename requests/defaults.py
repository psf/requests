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
:strict_mode: If true, Requests will do its best to follow RFCs (e.g. POST redirects).
:pool_maxsize: The maximium size of an HTTP connection pool.
:pool_connections: The number of active HTTP connection pools to use.
:encode_uri: If true, URIs will automatically be percent-encoded.
:trust_env: If true, the surrouding environment will be trusted (environ, netrc).
:param store_cookies: If false, the received cookies as part of the HTTP response would be ignored.

"""

SCHEMAS = ['http', 'https']

import platform
import sys

from . import __version__

defaults = dict()


_implementation = platform.python_implementation()

if _implementation == 'CPython':
    _implementation_version = platform.python_version()
elif _implementation == 'PyPy':
    _implementation_version = '%s.%s.%s' % (
                                                sys.pypy_version_info.major,
                                                sys.pypy_version_info.minor,
                                                sys.pypy_version_info.micro
                                            )
    if sys.pypy_version_info.releaselevel != 'final':
        _implementation_version = ''.join([_implementation_version, sys.pypy_version_info.releaselevel])
elif _implementation == 'Jython':
    # @@@ Is there a better way of getting this?
    _implementation_version = platform.python_version()
elif _implementation == 'IronPython':
    # @@@ Is there a better way of getting this?
    _implementation_version = platform.python_version()
else:
    _implementation_version = 'Unknown'


defaults['base_headers'] = {
    'User-Agent': " ".join([
            'python-requests/%s' % __version__,
            '%s/%s' % (_implementation, _implementation_version),
            '%s/%s' % (platform.system(), platform.release()),
        ]),
    'Accept': '*/*'
}

defaults['verbose'] = None
defaults['max_redirects'] = 30
defaults['pool_connections'] = 10
defaults['pool_maxsize'] = 10
defaults['max_retries'] = 0
defaults['danger_mode'] = False
defaults['safe_mode'] = False
defaults['strict_mode'] = False
defaults['keep_alive'] = True
defaults['encode_uri'] = True
defaults['trust_env'] = True
defaults['store_cookies'] = True
