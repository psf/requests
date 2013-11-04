# urllib3/util.py
# Copyright 2008-2013 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php


from base64 import b64encode
from binascii import hexlify, unhexlify
from collections import namedtuple
from hashlib import md5, sha1
from socket import error as SocketError, _GLOBAL_DEFAULT_TIMEOUT
import time

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
    from ssl import wrap_socket, CERT_NONE, PROTOCOL_SSLv23
    from ssl import SSLContext  # Modern SSL?
    from ssl import HAS_SNI  # Has SNI?
except ImportError:
    pass

from .packages import six
from .exceptions import LocationParseError, SSLError, TimeoutStateError


_Default = object()
# The default timeout to use for socket connections. This is the attribute used
# by httplib to define the default timeout


def current_time():
    """
    Retrieve the current time, this function is mocked out in unit testing.
    """
    return time.time()


class Timeout(object):
    """
    Utility object for storing timeout values.

    Example usage:

    .. code-block:: python

        timeout = urllib3.util.Timeout(connect=2.0, read=7.0)
        pool = HTTPConnectionPool('www.google.com', 80, timeout=timeout)
        pool.request(...) # Etc, etc

    :param connect:
        The maximum amount of time to wait for a connection attempt to a server
        to succeed. Omitting the parameter will default the connect timeout to
        the system default, probably `the global default timeout in socket.py
        <http://hg.python.org/cpython/file/603b4d593758/Lib/socket.py#l535>`_.
        None will set an infinite timeout for connection attempts.

    :type connect: integer, float, or None

    :param read:
        The maximum amount of time to wait between consecutive
        read operations for a response from the server. Omitting
        the parameter will default the read timeout to the system
        default, probably `the global default timeout in socket.py
        <http://hg.python.org/cpython/file/603b4d593758/Lib/socket.py#l535>`_.
        None will set an infinite timeout.

    :type read: integer, float, or None

    :param total:
        This combines the connect and read timeouts into one; the read timeout
        will be set to the time leftover from the connect attempt. In the
        event that both a connect timeout and a total are specified, or a read
        timeout and a total are specified, the shorter timeout will be applied.

        Defaults to None.

    :type total: integer, float, or None

    .. note::

        Many factors can affect the total amount of time for urllib3 to return
        an HTTP response. Specifically, Python's DNS resolver does not obey the
        timeout specified on the socket. Other factors that can affect total
        request time include high CPU load, high swap, the program running at a
        low priority level, or other behaviors. The observed running time for
        urllib3 to return a response may be greater than the value passed to
        `total`.

        In addition, the read and total timeouts only measure the time between
        read operations on the socket connecting the client and the server,
        not the total amount of time for the request to return a complete
        response. For most requests, the timeout is raised because the server
        has not sent the first byte in the specified time. This is not always
        the case; if a server streams one byte every fifteen seconds, a timeout
        of 20 seconds will not ever trigger, even though the request will
        take several minutes to complete.

        If your goal is to cut off any request after a set amount of wall clock
        time, consider having a second "watcher" thread to cut off a slow
        request.
    """

    #: A sentinel object representing the default timeout value
    DEFAULT_TIMEOUT = _GLOBAL_DEFAULT_TIMEOUT

    def __init__(self, total=None, connect=_Default, read=_Default):
        self._connect = self._validate_timeout(connect, 'connect')
        self._read = self._validate_timeout(read, 'read')
        self.total = self._validate_timeout(total, 'total')
        self._start_connect = None

    def __str__(self):
        return '%s(connect=%r, read=%r, total=%r)' % (
            type(self).__name__, self._connect, self._read, self.total)


    @classmethod
    def _validate_timeout(cls, value, name):
        """ Check that a timeout attribute is valid

        :param value: The timeout value to validate
        :param name: The name of the timeout attribute to validate. This is used
            for clear error messages
        :return: the value
        :raises ValueError: if the type is not an integer or a float, or if it
            is a numeric value less than zero
        """
        if value is _Default:
            return cls.DEFAULT_TIMEOUT

        if value is None or value is cls.DEFAULT_TIMEOUT:
            return value

        try:
            float(value)
        except (TypeError, ValueError):
            raise ValueError("Timeout value %s was %s, but it must be an "
                             "int or float." % (name, value))

        try:
            if value < 0:
                raise ValueError("Attempted to set %s timeout to %s, but the "
                                 "timeout cannot be set to a value less "
                                 "than 0." % (name, value))
        except TypeError: # Python 3
            raise ValueError("Timeout value %s was %s, but it must be an "
                             "int or float." % (name, value))

        return value

    @classmethod
    def from_float(cls, timeout):
        """ Create a new Timeout from a legacy timeout value.

        The timeout value used by httplib.py sets the same timeout on the
        connect(), and recv() socket requests. This creates a :class:`Timeout`
        object that sets the individual timeouts to the ``timeout`` value passed
        to this function.

        :param timeout: The legacy timeout value
        :type timeout: integer, float, sentinel default object, or None
        :return: a Timeout object
        :rtype: :class:`Timeout`
        """
        return Timeout(read=timeout, connect=timeout)

    def clone(self):
        """ Create a copy of the timeout object

        Timeout properties are stored per-pool but each request needs a fresh
        Timeout object to ensure each one has its own start/stop configured.

        :return: a copy of the timeout object
        :rtype: :class:`Timeout`
        """
        # We can't use copy.deepcopy because that will also create a new object
        # for _GLOBAL_DEFAULT_TIMEOUT, which socket.py uses as a sentinel to
        # detect the user default.
        return Timeout(connect=self._connect, read=self._read,
                       total=self.total)

    def start_connect(self):
        """ Start the timeout clock, used during a connect() attempt

        :raises urllib3.exceptions.TimeoutStateError: if you attempt
            to start a timer that has been started already.
        """
        if self._start_connect is not None:
            raise TimeoutStateError("Timeout timer has already been started.")
        self._start_connect = current_time()
        return self._start_connect

    def get_connect_duration(self):
        """ Gets the time elapsed since the call to :meth:`start_connect`.

        :return: the elapsed time
        :rtype: float
        :raises urllib3.exceptions.TimeoutStateError: if you attempt
            to get duration for a timer that hasn't been started.
        """
        if self._start_connect is None:
            raise TimeoutStateError("Can't get connect duration for timer "
                                    "that has not started.")
        return current_time() - self._start_connect

    @property
    def connect_timeout(self):
        """ Get the value to use when setting a connection timeout.

        This will be a positive float or integer, the value None
        (never timeout), or the default system timeout.

        :return: the connect timeout
        :rtype: int, float, :attr:`Timeout.DEFAULT_TIMEOUT` or None
        """
        if self.total is None:
            return self._connect

        if self._connect is None or self._connect is self.DEFAULT_TIMEOUT:
            return self.total

        return min(self._connect, self.total)

    @property
    def read_timeout(self):
        """ Get the value for the read timeout.

        This assumes some time has elapsed in the connection timeout and
        computes the read timeout appropriately.

        If self.total is set, the read timeout is dependent on the amount of
        time taken by the connect timeout. If the connection time has not been
        established, a :exc:`~urllib3.exceptions.TimeoutStateError` will be
        raised.

        :return: the value to use for the read timeout
        :rtype: int, float, :attr:`Timeout.DEFAULT_TIMEOUT` or None
        :raises urllib3.exceptions.TimeoutStateError: If :meth:`start_connect`
            has not yet been called on this object.
        """
        if (self.total is not None and
            self.total is not self.DEFAULT_TIMEOUT and
            self._read is not None and
            self._read is not self.DEFAULT_TIMEOUT):
            # in case the connect timeout has not yet been established.
            if self._start_connect is None:
                return self._read
            return max(0, min(self.total - self.get_connect_duration(),
                              self._read))
        elif self.total is not None and self.total is not self.DEFAULT_TIMEOUT:
            return max(0, self.total - self.get_connect_duration())
        else:
            return self._read


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

    @property
    def netloc(self):
        """Network location including host and port"""
        if self.port:
            return '%s:%d' % (self.host, self.port)
        return self.host


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
    # Additionally, this implementations does silly things to be optimal
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
        # Last '@' denotes end of auth part
        auth, url = url.rsplit('@', 1)

    # IPv6
    if url and url[0] == '[':
        host, url = url.split(']', 1)
        host += ']'

    # Port
    if ':' in url:
        _host, port = url.split(':', 1)

        if not host:
            host = _host

        if port:
            # If given, ports must be integers.
            if not port.isdigit():
                raise LocationParseError("Failed to parse: %s" % url)
            port = int(port)
        else:
            # Blank ports are cool, too. (rfc3986#section-3.2.3)
            port = None

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
                 basic_auth=None, proxy_basic_auth=None):
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

    :param proxy_basic_auth:
        Colon-separated username:password string for 'proxy-authorization: basic ...'
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

    if proxy_basic_auth:
        headers['proxy-authorization'] = 'Basic ' + \
            b64encode(six.b(proxy_basic_auth)).decode('utf-8')

    return headers


def is_connection_dropped(conn):  # Platform-specific
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

    if not poll:
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


def assert_fingerprint(cert, fingerprint):
    """
    Checks if given fingerprint matches the supplied certificate.

    :param cert:
        Certificate as bytes object.
    :param fingerprint:
        Fingerprint as string of hexdigits, can be interspersed by colons.
    """

    # Maps the length of a digest to a possible hash function producing
    # this digest.
    hashfunc_map = {
        16: md5,
        20: sha1
    }

    fingerprint = fingerprint.replace(':', '').lower()

    digest_length, rest = divmod(len(fingerprint), 2)

    if rest or digest_length not in hashfunc_map:
        raise SSLError('Fingerprint is of invalid length.')

    # We need encode() here for py32; works on py2 and p33.
    fingerprint_bytes = unhexlify(fingerprint.encode())

    hashfunc = hashfunc_map[digest_length]

    cert_digest = hashfunc(cert).digest()

    if not cert_digest == fingerprint_bytes:
        raise SSLError('Fingerprints did not match. Expected "{0}", got "{1}".'
                       .format(hexlify(fingerprint_bytes),
                               hexlify(cert_digest)))

def is_fp_closed(obj):
    """
    Checks whether a given file-like object is closed.

    :param obj:
        The file-like object to check.
    """
    if hasattr(obj, 'fp'):
        # Object is a container for another file-like object that gets released
        # on exhaustion (e.g. HTTPResponse)
        return obj.fp is None

    return obj.closed


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
