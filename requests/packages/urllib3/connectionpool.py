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
except ImportError:
    ssl = None
    BaseSSLError = None


from .filepost import encode_multipart_formdata
from .response import HTTPResponse
from .exceptions import (
    SSLError,
    MaxRetryError,
    TimeoutError,
    HostChangedError,
    EmptyPoolError)


log = logging.getLogger(__name__)

_Default = object()


## Connection objects (extension of httplib)

class VerifiedHTTPSConnection(HTTPSConnection):
    """
    Based on httplib.HTTPSConnection but wraps the socket with
    SSL certification.
    """

    def __init__(self):
        HTTPSConnection.__init__()
        self.cert_reqs = None
        self.ca_certs = None

    def set_cert(self, key_file=None, cert_file=None,
                 cert_reqs='CERT_NONE', ca_certs=None):
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

class ConnectionPool(object):
    pass


class HTTPConnectionPool(ConnectionPool):
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
        for _ in xrange(maxsize):
            self.pool.put(None)

        # These are mostly for testing and debugging purposes.
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
                log.info("Resetting dropped connection: %s" % self.host)
                conn.close()

        except Empty:
            if self.block:
                raise EmptyPoolError("Pool reached maximum size and no more "
                                     "connections are allowed.")
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
        except Full:
            # This should never happen if self.block == True
            log.warning("HttpConnectionPool is full, discarding connection: %s"
                        % self.host)

    def _make_request(self, conn, method, url, timeout=_Default,
                      **httplib_request_kw):
        """
        Perform a request on a given httplib connection object taken from our
        pool.
        """
        self.num_requests += 1

        if timeout is _Default:
            timeout = self.timeout

        conn.request(method, url, **httplib_request_kw)
        conn.sock.settimeout(timeout)
        httplib_response = conn.getresponse()

        log.debug("\"%s %s %s\" %s %s" %
                  (method, url,
                   conn._http_vsn_str, # pylint: disable-msg=W0212
                   httplib_response.status, httplib_response.length))

        return httplib_response


    def is_same_host(self, url):
        return (url.startswith('/') or
                get_host(url) == (self.scheme, self.host, self.port))

    def urlopen(self, method, url, body=None, headers=None, retries=3,
                redirect=True, assert_same_host=True, timeout=_Default,
                pool_timeout=None, release_conn=None, **response_kw):
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

        timeout
            If specified, overrides the default timeout for this one request.

        pool_timeout
            If set and the pool is set to block=True, then this method will
            block for ``pool_timeout`` seconds and raise EmptyPoolError if no
            connection is available within the time period.

        release_conn
            If False, then the urlopen call will not release the connection
            back into the pool once a response is received. This is useful if
            you're not preloading the response's content immediately. You will
            need to call ``r.release_conn()`` on the response ``r`` to return
            the connection back into the pool. If None, it takes the value of
            ``response_kw.get('preload_content', True)``.

        Additional parameters are passed to
        ``HTTPResponse.from_httplib(r, **response_kw)``
        """
        if headers is None:
            headers = self.headers

        if retries < 0:
            raise MaxRetryError("Max retries exceeded for url: %s" % url)

        if release_conn is None:
            release_conn = response_kw.get('preload_content', True)

        # Check host
        if assert_same_host and not self.is_same_host(url):
            host = "%s://%s" % (self.scheme, self.host)
            if self.port:
                host = "%s:%d" % (host, self.port)

            raise HostChangedError("Connection pool with host '%s' tried to "
                                   "open a foreign host: %s" % (host, url))

        # Request a connection from the queue
        conn = self._get_conn(timeout=pool_timeout)

        try:
            # Make the request on the httplib connection object
            httplib_response = self._make_request(conn, method, url,
                                                  timeout=timeout,
                                                  body=body, headers=headers)

            # Import httplib's response into our own wrapper object
            response = HTTPResponse.from_httplib(httplib_response,
                                                 pool=self,
                                                 connection=conn,
                                                 **response_kw)

            # The connection will be put back into the pool when
            # response.release_conn() is called (implicitly by response.read())

        except (SocketTimeout, Empty), e:
            # Timed out either by socket or queue
            raise TimeoutError("Request timed out after %f seconds" %
                               self.timeout)

        except (BaseSSLError), e:
            # SSL certificate error
            raise SSLError(e)

        except (HTTPException, SocketError), e:
            # Connection broken, discard. It will be replaced next _get_conn().
            conn = None

        finally:
            if release_conn:
                # Put the connection back to be reused
                response.release_conn() # Equivalent to self._put_conn(conn) but
                                        # tracks release state.

        if not conn:
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
                redirect=True, **response_kw):
        """
        Wrapper for performing GET with urlopen (see urlopen for more details).

        Supports an optional ``fields`` dictionary parameter key/value strings.
        If provided, they will be added to the url.
        """
        if fields:
            url += '?' + urlencode(fields)
        return self.urlopen('GET', url, headers=headers, retries=retries,
                            redirect=redirect, **response_kw)

    def post_url(self, url, fields=None, headers=None, retries=3,
                 redirect=True, encode_multipart=True, multipart_boundary=None,
                 **response_kw):
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
            body, content_type = encode_multipart_formdata(fields or {},
                                    boundary=multipart_boundary)
        else:
            body, content_type = (
                urlencode(fields or {}),
                'application/x-www-form-urlencoded')

        headers = headers or {}
        headers.update({'Content-Type': content_type})

        return self.urlopen('POST', url, body, headers=headers,
                            retries=retries, redirect=redirect, **response_kw)


class HTTPSConnectionPool(HTTPConnectionPool):
    """
    Same as HTTPConnectionPool, but HTTPS.
    """

    scheme = 'https'

    def __init__(self, host, port=None,
                 strict=False, timeout=None, maxsize=1,
                 block=False, headers=None,
                 key_file=None, cert_file=None,
                 cert_reqs='CERT_NONE', ca_certs=None):

        super(HTTPSConnectionPool, self).__init__(host, port,
                                                  strict, timeout, maxsize,
                                                  block, headers)
        self.key_file = key_file
        self.cert_file = cert_file
        self.cert_reqs = cert_reqs
        self.ca_certs = ca_certs

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
        url, _path = url.split('/', 1)
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
