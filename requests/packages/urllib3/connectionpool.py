import gzip
import zlib
import logging
import socket


from urllib import urlencode
from httplib import HTTPConnection, HTTPSConnection, HTTPException
from Queue import Queue, Empty, Full
from select import select
from socket import error as SocketError, timeout as SocketTimeout


try:
    import ssl
    BaseSSLError = ssl.SSLError
except ImportError, e:
    ssl = None
    BaseSSLError = None

try:
    from cStringIO import StringIO
except ImportError, e:
    from StringIO import StringIO


from filepost import encode_multipart_formdata


log = logging.getLogger(__name__)


## Exceptions

class HTTPError(Exception):
    "Base exception used by this module."
    pass


class SSLError(Exception):
    "Raised when SSL certificate fails in an HTTPS connection."
    pass


class MaxRetryError(HTTPError):
    "Raised when the maximum number of retries is exceeded."
    pass


class TimeoutError(HTTPError):
    "Raised when a socket timeout occurs."
    pass


class HostChangedError(HTTPError):
    "Raised when an existing pool gets a request for a foreign host."
    pass


## Response objects

class HTTPResponse(object):
    """
    HTTP Response container.

    Similar to httplib's HTTPResponse but the data is pre-loaded.
    """

    def __init__(self, data='', headers=None, status=0, version=0, reason=None,
                 strict=0):
        self.data = data
        self.headers = headers or {}
        self.status = status
        self.version = version
        self.reason = reason
        self.strict = strict

    @staticmethod
    def from_httplib(r):
        """
        Given an httplib.HTTPResponse instance, return a corresponding
        urllib3.HTTPResponse object.

        NOTE: This method will perform r.read() which will have side effects
        on the original http.HTTPResponse object.
        """
        tmp_data = r.read()
        try:
            if r.getheader('content-encoding') == 'gzip':
                log.debug("Received response with content-encoding: gzip, "
                          "decompressing with gzip.")

                gzipper = gzip.GzipFile(fileobj=StringIO(tmp_data))
                data = gzipper.read()
            elif r.getheader('content-encoding') == 'deflate':
                log.debug("Received response with content-encoding: deflate, "
                          "decompressing with zlib.")
                try:
                    data = zlib.decompress(tmp_data)
                except zlib.error, e:
                    data = zlib.decompress(tmp_data, -zlib.MAX_WBITS)
            else:
                data = tmp_data

        except IOError:
            raise HTTPError("Received response with content-encoding: %s, "
                            "but failed to decompress it." %
                            (r.getheader('content-encoding')))

        return HTTPResponse(data=data,
                    headers=dict(r.getheaders()),
                    status=r.status,
                    version=r.version,
                    reason=r.reason,
                    strict=r.strict)

    # Backwards-compatibility methods for httplib.HTTPResponse
    def getheaders(self):
        return self.headers

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


## Connection objects

class VerifiedHTTPSConnection(HTTPSConnection):
    """
    Based on httplib.HTTPSConnection but wraps the socket with
    SSL certification.
    """

    def set_cert(self, key_file=None, cert_file=None, cert_reqs='CERT_NONE',
                 ca_certs=None):
        ssl_req_scheme = {
            'CERT_NONE': ssl.CERT_NONE,
            'CERT_OPTIONAL': ssl.CERT_OPTIONAL,
            'CERT_REQUIRED': ssl.CERT_REQUIRED
        }

        self.key_file = key_file
        self.cert_file = cert_file
        self.cert_reqs = ssl_req_scheme.get(cert_reqs) or ssl.CERT_NONE
        self.ca_certs = ca_certs

    def connect(self):
        # Add certificate verification
        sock = socket.create_connection((self.host, self.port), self.timeout)

        # Wrap socket using verification with the root certs in
        # trusted_root_certs
        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                    cert_reqs=self.cert_reqs,
                                    ca_certs=self.ca_certs)


## Pool objects

class HTTPConnectionPool(object):
    """
    Thread-safe connection pool for one host.

    host
        Host used for this HTTP Connection (e.g. "localhost"), passed into
        httplib.HTTPConnection()

    port
        Port used for this HTTP Connection (None is equivalent to 80), passed
        into httplib.HTTPConnection()

    strict
        Causes BadStatusLine to be raised if the status line can't be parsed
        as a valid HTTP/1.0 or 1.1 status line, passed into
        httplib.HTTPConnection()

    timeout
        Socket timeout for each individual connection, can be a float. None
        disables timeout.

    maxsize
        Number of connections to save that can be reused. More than 1 is useful
        in multithreaded situations. If ``block`` is set to false, more
        connections will be created but they will not be saved once they've
        been used.

    block
        If set to True, no more than ``maxsize`` connections will be used at
        a time. When no free connections are available, the call will block
        until a connection has been released. This is a useful side effect for
        particular multithreaded situations where one does not want to use more
        than maxsize connections per host to prevent flooding.

    headers
        Headers to include with all requests, unless other headers are given
        explicitly.
    """

    scheme = 'http'

    def __init__(self, host, port=None, strict=False, timeout=None, maxsize=1,
                 block=False, headers=None):
        self.host = host
        self.port = port
        self.strict = strict
        self.timeout = timeout
        self.pool = Queue(maxsize)
        self.block = block
        self.headers = headers or {}

        # Fill the queue up so that doing get() on it will block properly
        [self.pool.put(None) for i in xrange(maxsize)]

        self.num_connections = 0
        self.num_requests = 0

    def _new_conn(self):
        """
        Return a fresh HTTPConnection.
        """
        self.num_connections += 1
        log.info("Starting new HTTP connection (%d): %s" %
                 (self.num_connections, self.host))
        return HTTPConnection(host=self.host, port=self.port)

    def _get_conn(self, timeout=None):
        """
        Get a connection. Will return a pooled connection if one is available.
        Otherwise, a fresh connection is returned.
        """
        conn = None
        try:
            conn = self.pool.get(block=self.block, timeout=timeout)

            # If this is a persistent connection, check if it got disconnected
            if conn and conn.sock and select([conn.sock], [], [], 0.0)[0]:
                # Either data is buffered (bad), or the connection is dropped.
                log.warning("Connection pool detected dropped "
                            "connection, resetting: %s" % self.host)
                conn.close()

        except Empty, e:
            pass  # Oh well, we'll create a new connection then

        return conn or self._new_conn()

    def _put_conn(self, conn):
        """
        Put a connection back into the pool.
        If the pool is already full, the connection is discarded because we
        exceeded maxsize. If connections are discarded frequently, then maxsize
        should be increased.
        """
        try:
            self.pool.put(conn, block=False)
        except Full, e:
            # This should never happen if self.block == True
            log.warning("HttpConnectionPool is full, discarding connection: %s"
                        % self.host)

    def is_same_host(self, url):
        return (url.startswith('/') or
                get_host(url) == (self.scheme, self.host, self.port))

    def urlopen(self, method, url, body=None, headers=None, retries=3,
                redirect=True, assert_same_host=True):
        """
        Get a connection from the pool and perform an HTTP request.

        method
            HTTP request method (such as GET, POST, PUT, etc.)

        body
            Data to send in the request body (useful for creating
            POST requests, see HTTPConnectionPool.post_url for
            more convenience).

        headers
            Dictionary of custom headers to send, such as User-Agent,
            If-None-Match, etc. If None, pool headers are used. If provided,
            these headers completely replace any pool-specific headers.

        retries
            Number of retries to allow before raising
            a MaxRetryError exception.

        redirect
            Automatically handle redirects (status codes 301, 302, 303, 307),
            each redirect counts as a retry.

        assert_same_host
            If True, will make sure that the host of the pool requests is
            consistent else will raise HostChangedError. When False, you can
            use the pool on an HTTP proxy and request foreign hosts.
        """
        if headers == None:
            headers = self.headers

        if retries < 0:
            raise MaxRetryError("Max retries exceeded for url: %s" % url)

        # Check host
        if assert_same_host and not self.is_same_host(url):
            host = "%s://%s" % (self.scheme, self.host)
            if self.port:
                host = "%s:%d" % (host, self.port)

            raise HostChangedError("Connection pool with host '%s' tried to "
                                   "open a foreign host: %s" % (host, url))

        try:
            # Request a connection from the queue
            conn = self._get_conn()

            # Make the request
            self.num_requests += 1
            conn.request(method, url, body=body, headers=headers)
            conn.sock.settimeout(self.timeout)
            httplib_response = conn.getresponse()
            log.debug("\"%s %s %s\" %s %s" %
                      (method, url, conn._http_vsn_str,
                       httplib_response.status, httplib_response.length))

            # from_httplib will perform httplib_response.read() which will have
            # the side effect of letting us use this connection for another
            # request.
            response = HTTPResponse.from_httplib(httplib_response)

            # Put the connection back to be reused
            self._put_conn(conn)

        except (SocketTimeout, Empty), e:
            # Timed out either by socket or queue
            raise TimeoutError("Request timed out after %f seconds" %
                               self.timeout)

        except (BaseSSLError), e:
            # SSL certificate error
            raise SSLError(e)

        except (HTTPException, SocketError), e:
            log.warn("Retrying (%d attempts remain) after connection "
                     "broken by '%r': %s" % (retries, e, url))
            return self.urlopen(method, url, body, headers, retries - 1,
                                redirect, assert_same_host)  # Try again

        # Handle redirection
        if (redirect and
            response.status in [301, 302, 303, 307] and
            'location' in response.headers):  # Redirect, retry
            log.info("Redirecting %s -> %s" %
                     (url, response.headers.get('location')))
            return self.urlopen(method, response.headers.get('location'), body,
                                headers, retries - 1, redirect,
                                assert_same_host)

        return response

    def get_url(self, url, fields=None, headers=None, retries=3,
                redirect=True):
        """
        Wrapper for performing GET with urlopen (see urlopen for more details).

        Supports an optional ``fields`` dictionary parameter key/value strings.
        If provided, they will be added to the url.
        """
        if fields:
            url += '?' + urlencode(fields)
        return self.urlopen('GET', url, headers=headers, retries=retries,
                            redirect=redirect)

    def post_url(self, url, fields=None, headers=None, retries=3,
                 redirect=True, encode_multipart=True):
        """
        Wrapper for performing POST with urlopen (see urlopen
        for more details).

        Supports an optional ``fields`` parameter of key/value strings AND
        key/filetuple. A filetuple is a (filename, data) tuple. For example:

        fields = {
            'foo': 'bar',
            'foofile': ('foofile.txt', 'contents of foofile'),
        }

        If encode_multipart=True (default), then
        ``urllib3.filepost.encode_multipart_formdata`` is used to encode the
        payload with the appropriate content type. Otherwise
        ``urllib.urlencode`` is used with 'application/x-www-form-urlencoded'
        content type.

        Multipart encoding must be used when posting files, and it's reasonably
        safe to use it other times too. It may break request signing, such as
        OAuth.

        NOTE: If ``headers`` are supplied, the 'Content-Type' value will be
        overwritten because it depends on the dynamic random boundary string
        which is used to compose the body of the request.
        """
        if encode_multipart:
            body, content_type = encode_multipart_formdata(fields or {})
        else:
            body, content_type = (
                urlencode(fields or {}),
                'application/x-www-form-urlencoded')

        headers = headers or {}
        headers.update({'Content-Type': content_type})

        return self.urlopen('POST', url, body, headers=headers,
                            retries=retries, redirect=redirect)


class HTTPSConnectionPool(HTTPConnectionPool):
    """
    Same as HTTPConnectionPool, but HTTPS.
    """

    scheme = 'https'

    def __init__(self, host, port=None, strict=False, timeout=None, maxsize=1,
                 block=False, headers=None, key_file=None,
                 cert_file=None, cert_reqs='CERT_NONE', ca_certs=None):
        self.host = host
        self.port = port
        self.strict = strict
        self.timeout = timeout
        self.pool = Queue(maxsize)
        self.block = block
        self.headers = headers or {}

        self.key_file = key_file
        self.cert_file = cert_file
        self.cert_reqs = cert_reqs
        self.ca_certs = ca_certs

        # Fill the queue up so that doing get() on it will block properly
        [self.pool.put(None) for i in xrange(maxsize)]

        self.num_connections = 0
        self.num_requests = 0

    def _new_conn(self):
        """
        Return a fresh HTTPSConnection.
        """
        self.num_connections += 1
        log.info("Starting new HTTPS connection (%d): %s"
                 % (self.num_connections, self.host))

        if not ssl:
            return HTTPSConnection(host=self.host, port=self.port)

        connection = VerifiedHTTPSConnection(host=self.host, port=self.port)
        connection.set_cert(key_file=self.key_file, cert_file=self.cert_file,
                            cert_reqs=self.cert_reqs, ca_certs=self.ca_certs)
        return connection


## Helpers

def make_headers(keep_alive=None, accept_encoding=None, user_agent=None,
                 basic_auth=None):
    """
    Shortcuts for generating request headers.

    keep_alive
        If true, adds 'connection: keep-alive' header.

    accept_encoding
        Can be a boolean, list, or string.
        True translates to 'gzip,deflate'.
        List will get joined by comma.
        String will be used as provided.

    user_agent
        String representing the user-agent you want, such as
        "python-urllib3/0.6"

    basic_auth
        Colon-separated username:password string for 'authorization: basic ...'
        auth header.
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
            basic_auth.encode('base64').strip()

    return headers


def get_host(url):
    """
    Given a url, return its scheme, host and port (None if it's not there).

    For example:
    >>> get_host('http://google.com/mail/')
    http, google.com, None
    >>> get_host('google.com:80')
    http, google.com, 80
    """
    # This code is actually similar to urlparse.urlsplit, but much
    # simplified for our needs.
    port = None
    scheme = 'http'
    if '//' in url:
        scheme, url = url.split('://', 1)
    if '/' in url:
        url, path = url.split('/', 1)
    if ':' in url:
        url, port = url.split(':', 1)
        port = int(port)
    return scheme, url, port


def connection_from_url(url, **kw):
    """
    Given a url, return an HTTP(S)ConnectionPool instance of its host.

    This is a shortcut for not having to determine the host of the url
    before creating an HTTP(S)ConnectionPool instance.

    Passes on whatever kw arguments to the constructor of
    HTTP(S)ConnectionPool. (e.g. timeout, maxsize, block)
    """
    scheme, host, port = get_host(url)
    if scheme == 'https':
        return HTTPSConnectionPool(host, port=port, **kw)
    else:
        return HTTPConnectionPool(host, port=port, **kw)
