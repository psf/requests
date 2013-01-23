# urllib3/util.py
# Copyright 2008-2012 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php


from base64 import b64encode
from collections import namedtuple
from socket import error as SocketError

try:
    from select import poll, POLLIN
except ImportError:  # `poll` doesn't exist on OSX and other platforms
    poll = False
    try:
        from select import select
    except ImportError:  # `select` doesn't exist on AppEngine.
        select = False

try:  # Test for SSL features
    SSLContext = None
    HAS_SNI = False

    import ssl
    from ssl import wrap_socket, CERT_NONE, SSLError, PROTOCOL_SSLv23
    from ssl import SSLContext  # Modern SSL?
    from ssl import HAS_SNI  # Has SNI?
except ImportError:
    pass


from .packages import six
from .exceptions import LocationParseError


class Url(namedtuple('Url', ['scheme', 'auth', 'host', 'port', 'path', 'query', 'fragment'])):
    """
    Datastructure for representing an HTTP URL. Used as a return value for
    :func:`parse_url`.
    """
    slots = ()

    def __new__(cls, scheme=None, auth=None, host=None, port=None, path=None, query=None, fragment=None):
        return super(Url, cls).__new__(cls, scheme, auth, host, port, path, query, fragment)

    @property
    def hostname(self):
        """For backwards-compatibility with urlparse. We're nice like that."""
        return self.host

    @property
    def request_uri(self):
        """Absolute path including the query string."""
        uri = self.path or '/'

        if self.query is not None:
            uri += '?' + self.query

        return uri


def split_first(s, delims):
    """
    Given a string and an iterable of delimiters, split on the first found
    delimiter. Return two split parts and the matched delimiter.

    If not found, then the first part is the full input string.

    Example: ::

        >>> split_first('foo/bar?baz', '?/=')
        ('foo', 'bar?baz', '/')
        >>> split_first('foo/bar?baz', '123')
        ('foo/bar?baz', '', None)

    Scales linearly with number of delims. Not ideal for large number of delims.
    """
    min_idx = None
    min_delim = None
    for d in delims:
        idx = s.find(d)
        if idx < 0:
            continue

        if min_idx is None or idx < min_idx:
            min_idx = idx
            min_delim = d

    if min_idx is None or min_idx < 0:
        return s, '', None

    return s[:min_idx], s[min_idx+1:], min_delim


def parse_url(url):
    """
    Given a url, return a parsed :class:`.Url` namedtuple. Best-effort is
    performed to parse incomplete urls. Fields not provided will be None.

    Partly backwards-compatible with :mod:`urlparse`.

    Example: ::

        >>> parse_url('http://google.com/mail/')
        Url(scheme='http', host='google.com', port=None, path='/', ...)
        >>> parse_url('google.com:80')
        Url(scheme=None, host='google.com', port=80, path=None, ...)
        >>> parse_url('/foo?bar')
        Url(scheme=None, host=None, port=None, path='/foo', query='bar', ...)
    """

    # While this code has overlap with stdlib's urlparse, it is much
    # simplified for our needs and less annoying.
    # Additionally, this imeplementations does silly things to be optimal
    # on CPython.

    scheme = None
    auth = None
    host = None
    port = None
    path = None
    fragment = None
    query = None

    # Scheme
    if '://' in url:
        scheme, url = url.split('://', 1)

    # Find the earliest Authority Terminator
    # (http://tools.ietf.org/html/rfc3986#section-3.2)
    url, path_, delim = split_first(url, ['/', '?', '#'])

    if delim:
        # Reassemble the path
        path = delim + path_

    # Auth
    if '@' in url:
        auth, url = url.split('@', 1)

    # IPv6
    if url and url[0] == '[':
        host, url = url[1:].split(']', 1)

    # Port
    if ':' in url:
        _host, port = url.split(':', 1)

        if not host:
            host = _host

        if not port.isdigit():
            raise LocationParseError("Failed to parse: %s" % url)

        port = int(port)

    elif not host and url:
        host = url

    if not path:
        return Url(scheme, auth, host, port, path, query, fragment)

    # Fragment
    if '#' in path:
        path, fragment = path.split('#', 1)

    # Query
    if '?' in path:
        path, query = path.split('?', 1)

    return Url(scheme, auth, host, port, path, query, fragment)


def get_host(url):
    """
    Deprecated. Use :func:`.parse_url` instead.
    """
    p = parse_url(url)
    return p.scheme or 'http', p.hostname, p.port


def make_headers(keep_alive=None, accept_encoding=None, user_agent=None,
                 basic_auth=None):
    """
    Shortcuts for generating request headers.

    :param keep_alive:
        If ``True``, adds 'connection: keep-alive' header.

    :param accept_encoding:
        Can be a boolean, list, or string.
        ``True`` translates to 'gzip,deflate'.
        List will get joined by comma.
        String will be used as provided.

    :param user_agent:
        String representing the user-agent you want, such as
        "python-urllib3/0.6"

    :param basic_auth:
        Colon-separated username:password string for 'authorization: basic ...'
        auth header.

    Example: ::

        >>> make_headers(keep_alive=True, user_agent="Batman/1.0")
        {'connection': 'keep-alive', 'user-agent': 'Batman/1.0'}
        >>> make_headers(accept_encoding=True)
        {'accept-encoding': 'gzip,deflate'}
    """
    headers = {}
    if accept_encoding:
        if isinstance(accept_encoding, str):
            pass
        elif isinstance(accept_encoding, list):
            accept_encoding = ','.join(accept_encoding)
        else:
            accept_encoding = 'gzip,deflate'
        headers['accept-encoding'] = accept_encoding

    if user_agent:
        headers['user-agent'] = user_agent

    if keep_alive:
        headers['connection'] = 'keep-alive'

    if basic_auth:
        headers['authorization'] = 'Basic ' + \
            b64encode(six.b(basic_auth)).decode('utf-8')

    return headers


def is_connection_dropped(conn):
    """
    Returns True if the connection is dropped and should be closed.

    :param conn:
        :class:`httplib.HTTPConnection` object.

    Note: For platforms like AppEngine, this will always return ``False`` to
    let the platform handle connection recycling transparently for us.
    """
    sock = getattr(conn, 'sock', False)
    if not sock: # Platform-specific: AppEngine
        return False

    if not poll: # Platform-specific
        if not select: # Platform-specific: AppEngine
            return False

        try:
            return select([sock], [], [], 0.0)[0]
        except SocketError:
            return True

    # This version is better on platforms that support it.
    p = poll()
    p.register(sock, POLLIN)
    for (fno, ev) in p.poll(0.0):
        if fno == sock.fileno():
            # Either data is buffered (bad), or the connection is dropped.
            return True


def resolve_cert_reqs(candidate):
    """
    Resolves the argument to a numeric constant, which can be passed to
    the wrap_socket function/method from the ssl module.
    Defaults to :data:`ssl.CERT_NONE`.
    If given a string it is assumed to be the name of the constant in the
    :mod:`ssl` module or its abbrevation.
    (So you can specify `REQUIRED` instead of `CERT_REQUIRED`.
    If it's neither `None` nor a string we assume it is already the numeric
    constant which can directly be passed to wrap_socket.
    """
    if candidate is None:
        return CERT_NONE

    if isinstance(candidate, str):
        res = getattr(ssl, candidate, None)
        if res is None:
            res = getattr(ssl, 'CERT_' + candidate)
        return res

    return candidate


def resolve_ssl_version(candidate):
    """
    like resolve_cert_reqs
    """
    if candidate is None:
        return PROTOCOL_SSLv23

    if isinstance(candidate, str):
        res = getattr(ssl, candidate, None)
        if res is None:
            res = getattr(ssl, 'PROTOCOL_' + candidate)
        return res

    return candidate

if SSLContext is not None:  # Python 3.2+
    def ssl_wrap_socket(sock, keyfile=None, certfile=None, cert_reqs=None,
                        ca_certs=None, server_hostname=None,
                        ssl_version=None):
        """
        All arguments except `server_hostname` have the same meaning as for
        :func:`ssl.wrap_socket`

        :param server_hostname:
            Hostname of the expected certificate
        """
        context = SSLContext(ssl_version)
        context.verify_mode = cert_reqs
        if ca_certs:
            try:
                context.load_verify_locations(ca_certs)
            # Py32 raises IOError
            # Py33 raises FileNotFoundError
            except Exception as e:  # Reraise as SSLError
                raise SSLError(e)
        if certfile:
            # FIXME: This block needs a test.
            context.load_cert_chain(certfile, keyfile)
        if HAS_SNI:  # Platform-specific: OpenSSL with enabled SNI
            return context.wrap_socket(sock, server_hostname=server_hostname)
        return context.wrap_socket(sock)

else:  # Python 3.1 and earlier
    def ssl_wrap_socket(sock, keyfile=None, certfile=None, cert_reqs=None,
                        ca_certs=None, server_hostname=None,
                        ssl_version=None):
        return wrap_socket(sock, keyfile=keyfile, certfile=certfile,
                           ca_certs=ca_certs, cert_reqs=cert_reqs,
                           ssl_version=ssl_version)
