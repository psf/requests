# urllib3/connection.py
# Copyright 2008-2013 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php

import socket
from socket import timeout as SocketTimeout

try: # Python 3
    from http.client import HTTPConnection, HTTPException
except ImportError:
    from httplib import HTTPConnection, HTTPException

class DummyConnection(object):
    "Used to detect a failed ConnectionCls import."
    pass

try: # Compiled with SSL?
    ssl = None
    HTTPSConnection = DummyConnection

    class BaseSSLError(BaseException):
        pass

    try: # Python 3
        from http.client import HTTPSConnection
    except ImportError:
        from httplib import HTTPSConnection

    import ssl
    BaseSSLError = ssl.SSLError

except (ImportError, AttributeError): # Platform-specific: No SSL.
    pass

from .exceptions import (
    ConnectTimeoutError,
)
from .packages.ssl_match_hostname import match_hostname
from .util import (
    assert_fingerprint,
    resolve_cert_reqs,
    resolve_ssl_version,
    ssl_wrap_socket,
)

class VerifiedHTTPSConnection(HTTPSConnection):
    """
    Based on httplib.HTTPSConnection but wraps the socket with
    SSL certification.
    """
    cert_reqs = None
    ca_certs = None
    ssl_version = None

    def set_cert(self, key_file=None, cert_file=None,
                 cert_reqs=None, ca_certs=None,
                 assert_hostname=None, assert_fingerprint=None):

        self.key_file = key_file
        self.cert_file = cert_file
        self.cert_reqs = cert_reqs
        self.ca_certs = ca_certs
        self.assert_hostname = assert_hostname
        self.assert_fingerprint = assert_fingerprint

    def connect(self):
        # Add certificate verification
        try:
            sock = socket.create_connection(
                address=(self.host, self.port),
                timeout=self.timeout,
            )
        except SocketTimeout:
                raise ConnectTimeoutError(
                    self, "Connection to %s timed out. (connect timeout=%s)" %
                    (self.host, self.timeout))

        resolved_cert_reqs = resolve_cert_reqs(self.cert_reqs)
        resolved_ssl_version = resolve_ssl_version(self.ssl_version)

        if self._tunnel_host:
            self.sock = sock
            # Calls self._set_hostport(), so self.host is
            # self._tunnel_host below.
            self._tunnel()

        # Wrap socket using verification with the root certs in
        # trusted_root_certs
        self.sock = ssl_wrap_socket(sock, self.key_file, self.cert_file,
                                    cert_reqs=resolved_cert_reqs,
                                    ca_certs=self.ca_certs,
                                    server_hostname=self.host,
                                    ssl_version=resolved_ssl_version)

        if resolved_cert_reqs != ssl.CERT_NONE:
            if self.assert_fingerprint:
                assert_fingerprint(self.sock.getpeercert(binary_form=True),
                                   self.assert_fingerprint)
            elif self.assert_hostname is not False:
                match_hostname(self.sock.getpeercert(),
                               self.assert_hostname or self.host)


if ssl:
    HTTPSConnection = VerifiedHTTPSConnection
