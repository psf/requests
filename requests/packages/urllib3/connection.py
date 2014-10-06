import datetime
import sys
import socket
from socket import timeout as SocketTimeout
import warnings
from .packages import six
import asyncio


from yieldfrom.httpclient import HTTPConnection as _HTTPConnection, HTTPSConnection as _HTTPSConnection, \
    HTTPException, create_connection as _create_connection

#try:  # Python 3
#    from http.client import HTTPConnection as _HTTPConnection, HTTPException
#except ImportError:
#    from httplib import HTTPConnection as _HTTPConnection, HTTPException


class DummyConnection(object):
    "Used to detect a failed ConnectionCls import."
    pass


try:  # Compiled with SSL?
    HTTPSConnection = DummyConnection
    import ssl
    BaseSSLError = ssl.SSLError
except (ImportError, AttributeError):  # Platform-specific: No SSL.
    ssl = None

    class BaseSSLError(BaseException):
        pass


try:  # Python 3:
    # Not a no-op, we're adding this to the namespace so it can be imported.
    ConnectionError = ConnectionError
except NameError:  # Python 2:
    class ConnectionError(Exception):
        pass


from .exceptions import (
    ConnectTimeoutError,
    SystemTimeWarning,
    ProtocolError
)
from .packages.ssl_match_hostname import match_hostname

from .util.ssl_ import (
    resolve_cert_reqs,
    resolve_ssl_version,
    #ssl_wrap_socket,
    create_context,
    assert_fingerprint,
)


#from .util import connection

port_by_scheme = {
    'http': 80,
    'https': 443,
}

RECENT_DATE = datetime.date(2014, 1, 1)

@asyncio.coroutine
def create_connection(address, *args, **kwargs):
    try:
        _r = yield from _create_connection(address, *args, **kwargs)
        return _r
    except (OSError, asyncio.TimeoutError) as e:
        raise ConnectTimeoutError
    except socket.gaierror as e:
        raise ProtocolError('socket.gaierror')
    except:
        raise

class HTTPConnection(_HTTPConnection):

    def __init__(self, *args, **kwargs):
        kwargs.pop('strict', None)
        kwargs.pop('socket_options', None)
        _HTTPConnection.__init__(self, *args, **kwargs)
        self._create_connection = create_connection


# class HTTPConnection(_HTTPConnection, object):
#     """
#     Based on httplib.HTTPConnection but provides an extra constructor
#     backwards-compatibility layer between older and newer Pythons.
#
#     Additional keyword parameters are used to configure attributes of the connection.
#     Accepted parameters include:
#
#       - ``strict``: See the documentation on :class:`urllib3.connectionpool.HTTPConnectionPool`
#       - ``source_address``: Set the source address for the current connection.
#
#         .. note:: This is ignored for Python 2.6. It is only applied for 2.7 and 3.x
#
#       - ``socket_options``: Set specific options on the underlying socket. If not specified, then
#         defaults are loaded from ``HTTPConnection.default_socket_options`` which includes disabling
#         Nagle's algorithm (sets TCP_NODELAY to 1) unless the connection is behind a proxy.
#
#         For example, if you wish to enable TCP Keep Alive in addition to the defaults,
#         you might pass::
#
#             HTTPConnection.default_socket_options + [
#                 (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
#             ]
#
#         Or you may want to disable the defaults by passing an empty list (e.g., ``[]``).
#     """
#
#     default_port = port_by_scheme['http']
#
#     #: Disable Nagle's algorithm by default.
#     #: ``[(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]``
#     default_socket_options = [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]
#
#     #: Whether this connection verifies the host's certificate.
#     is_verified = False
#
#     def __init__(self, *args, **kw):
#         if six.PY3:  # Python 3
#             kw.pop('strict', None)
#
#         # Pre-set source_address in case we have an older Python like 2.6.
#         self.source_address = kw.get('source_address')
#
#         if sys.version_info < (2, 7):  # Python 2.6
#             # _HTTPConnection on Python 2.6 will balk at this keyword arg, but
#             # not newer versions. We can still use it when creating a
#             # connection though, so we pop it *after* we have saved it as
#             # self.source_address.
#             kw.pop('source_address', None)
#
#         #: The socket options provided by the user. If no options are
#         #: provided, we use the default options.
#         self.socket_options = kw.pop('socket_options', self.default_socket_options)
#
#         # Superclass also sets self.source_address in Python 2.7+.
#         _HTTPConnection.__init__(self, *args, **kw)
#
#     def _new_conn(self):
#         """ Establish a socket connection and set nodelay settings on it.
#
#         :return: New socket connection.
#         """
#         extra_kw = {}
#         if self.source_address:
#             extra_kw['source_address'] = self.source_address
#
#         if self.socket_options:
#             extra_kw['socket_options'] = self.socket_options
#
#         try:
#             #conn = connection.create_connection(
#             #    (self.host, self.port), self.timeout, **extra_kw)
#             conn = _HTTPConnection.
#
#         except SocketTimeout:
#             raise ConnectTimeoutError(
#                 self, "Connection to %s timed out. (connect timeout=%s)" %
#                 (self.host, self.timeout))
#
#         return conn
#
#     def _prepare_conn(self, conn):
#         self.sock = conn
#         # the _tunnel_host attribute was added in python 2.6.3 (via
#         # http://hg.python.org/cpython/rev/0f57b30a152f) so pythons 2.6(0-2) do
#         # not have them.
#         if getattr(self, '_tunnel_host', None):
#             # TODO: Fix tunnel so it doesn't depend on self.sock state.
#             self._tunnel()
#             # Mark this connection as not reusable
#             self.auto_open = 0
#
#     def connect(self):
#         conn = self._new_conn()
#         self._prepare_conn(conn)


class HTTPSConnection(HTTPConnection):

    default_port = port_by_scheme['https']

    def __init__(self, host, port=None, key_file=None, cert_file=None, strict=None, context=None,
                  source_address=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, check_hostname=False,
                  **kw):

        HTTPConnection.__init__(self, host, port, timeout=timeout, source_address=source_address, **kw)

        self.key_file = key_file
        self.cert_file = cert_file

        if context is None:
            context = ssl._create_stdlib_context()
        self._context = context
        self._check_hostname = check_hostname

        self.is_verified = False

    @asyncio.coroutine
    def connect(self):

        if self._tunnel_host:
            server_hostname = self._tunnel_host
        else:
            server_hostname = self.host
        sni_hostname = server_hostname if ssl.HAS_SNI else None  # will be useful eventually

        self.sock = yield from self._create_connection((self.host, self.port), self.timeout,
                                                       self.source_address, ssl=self._context,
                                                       server_hostname=server_hostname)

        if self._tunnel_host:
            yield from self._tunnel()
            self.auto_open = 0

        # self.sock = self._context.wrap_socket(self.sock, server_hostname=sni_hostname,
        #                                       do_handshake_on_connect=False)
        if not self._context.check_hostname and self._check_hostname:
            try:
                ssl.match_hostname(self.sock.getpeercert(), server_hostname)
            except Exception as e:
                self.close()
                raise


class VerifiedHTTPSConnection(HTTPSConnection):
    """
    Based on httplib.HTTPSConnection but wraps the socket with
    SSL certification.
    """
    cert_reqs = None
    ca_certs = None
    ssl_version = None
    assert_fingerprint = None

    def set_cert(self, key_file=None, cert_file=None,
                 cert_reqs=None, ca_certs=None,
                 assert_hostname=None, assert_fingerprint=None):

        self.key_file = key_file
        self.cert_file = cert_file
        self.cert_reqs = cert_reqs
        self.ca_certs = ca_certs
        self.assert_hostname = assert_hostname
        self.assert_fingerprint = assert_fingerprint

    @asyncio.coroutine
    def connect(self):
        # Add certificate verification

        resolved_cert_reqs = resolve_cert_reqs(self.cert_reqs)
        resolved_ssl_version = resolve_ssl_version(self.ssl_version)

        is_time_off = datetime.date.today() < RECENT_DATE
        if is_time_off:
            warnings.warn((
                'System time is way off (before {0}). This will probably '
                'lead to SSL verification errors').format(RECENT_DATE),
                SystemTimeWarning
            )

        server_hostname =  self._tunnel_host or self.host

        self._context = create_context(self.key_file, self.cert_file,
                                     cert_reqs=resolved_cert_reqs,
                                     ca_certs=self.ca_certs,
                                     server_hostname=server_hostname,
                                     ssl_version=resolved_ssl_version)

        yield from super(VerifiedHTTPSConnection, self).connect()

        # # Wrap socket using verification with the root certs in
        # # trusted_root_certs
        # self.sock = ssl_wrap_socket(conn, self.key_file, self.cert_file,
        #                             cert_reqs=resolved_cert_reqs,
        #                             ca_certs=self.ca_certs,
        #                             server_hostname=hostname,
        #                             ssl_version=resolved_ssl_version)

        if self.assert_fingerprint:
            assert_fingerprint(self.sock.getpeercert(binary_form=True),
                               self.assert_fingerprint)
        elif resolved_cert_reqs != ssl.CERT_NONE \
                and self.assert_hostname is not False:
            match_hostname(self.sock.getpeercert(),
                           self.assert_hostname or server_hostname)

        self.is_verified = (resolved_cert_reqs == ssl.CERT_REQUIRED
                            or self.assert_fingerprint is not None)


if ssl:
    # Make a copy for testing.
    UnverifiedHTTPSConnection = HTTPSConnection
    HTTPSConnection = VerifiedHTTPSConnection
