# -*- coding: utf-8 -*-

"""
requests.adapters
~~~~~~~~~~~~~~~~~

This module contains the transport adapters that Requests uses to define
and maintain connections.
"""

from cgi import escape as html_escape
from email.utils import formatdate
import errno
from mimetypes import guess_type as guess_mime_type
from os import listdir, readlink, stat, strerror, unlink
from os.path import exists
import socket
from stat import S_ISDIR, S_ISLNK, S_ISREG
from StringIO import StringIO
from traceback import format_exc
from urllib import quote as url_quote, unquote as url_unquote

from .models import Response
from .packages.urllib3.poolmanager import PoolManager, proxy_from_url
from .packages.urllib3.response import HTTPResponse
from .hooks import dispatch_hook
from .compat import urlparse, basestring, urldefrag
from .utils import (DEFAULT_CA_BUNDLE_PATH, get_encoding_from_headers,
                    prepend_scheme_if_needed)
from .structures import CaseInsensitiveDict
from .packages.urllib3.exceptions import MaxRetryError
from .packages.urllib3.exceptions import TimeoutError
from .packages.urllib3.exceptions import SSLError as _SSLError
from .packages.urllib3.exceptions import HTTPError as _HTTPError
from .cookies import extract_cookies_to_jar
from .exceptions import ConnectionError, Timeout, SSLError

DEFAULT_POOLSIZE = 10
DEFAULT_RETRIES = 0


class BaseAdapter(object):
    """The Base Transport Adapter"""

    def __init__(self):
        super(BaseAdapter, self).__init__()

    def send(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


class HTTPAdapter(BaseAdapter):
    """Built-In HTTP Adapter for Urllib3."""
    def __init__(self, pool_connections=DEFAULT_POOLSIZE, pool_maxsize=DEFAULT_POOLSIZE):
        self.max_retries = DEFAULT_RETRIES
        self.config = {}

        super(HTTPAdapter, self).__init__()

        self.init_poolmanager(pool_connections, pool_maxsize)

    def init_poolmanager(self, connections, maxsize):
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize)

    def cert_verify(self, conn, url, verify, cert):
        if url.startswith('https') and verify:

            cert_loc = None

            # Allow self-specified cert location.
            if verify is not True:
                cert_loc = verify

            if not cert_loc:
                cert_loc = DEFAULT_CA_BUNDLE_PATH

            if not cert_loc:
                raise Exception("Could not find a suitable SSL CA certificate bundle.")

            conn.cert_reqs = 'CERT_REQUIRED'
            conn.ca_certs = cert_loc
        else:
            conn.cert_reqs = 'CERT_NONE'
            conn.ca_certs = None

        if cert:
            if not isinstance(cert, basestring):
                conn.cert_file = cert[0]
                conn.key_file = cert[1]
            else:
                conn.cert_file = cert

    def build_response(self, req, resp):
        response = Response()

        # Fallback to None if there's no status_code, for whatever reason.
        response.status_code = getattr(resp, 'status', None)

        # Make headers case-insensitive.
        response.headers = CaseInsensitiveDict(getattr(resp, 'headers', {}))

        # Set encoding.
        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = resp
        response.reason = response.raw.reason

        if isinstance(req.url, bytes):
            response.url = req.url.decode('utf-8')
        else:
            response.url = req.url

        # Add new cookies from the server.
        extract_cookies_to_jar(response.cookies, req, resp)

        # Give the Response some context.
        response.request = req
        response.connection = self

        # Run the Response hook.
        response = dispatch_hook('response', req.hooks, response)
        return response

    def get_connection(self, url, proxies=None):
        """Returns a connection for the given URL."""
        proxies = proxies or {}
        proxy = proxies.get(urlparse(url).scheme)

        if proxy:
            proxy = prepend_scheme_if_needed(proxy, urlparse(url).scheme)
            conn = proxy_from_url(proxy)
        else:
            conn = self.poolmanager.connection_from_url(url)

        return conn

    def close(self):
        """Dispose of any internal state.

        Currently, this just closes the PoolManager, which closes pooled
        connections.
        """
        self.poolmanager.clear()

    def request_url(self, request, proxies):
        """Obtain the url to use when making the final request.

        If the message is being sent through a proxy, the full URL has to be
        used. Otherwise, we should only use the path portion of the URL."""
        proxies = proxies or {}
        proxy = proxies.get(urlparse(request.url).scheme)

        if proxy:
            url, _ = urldefrag(request.url)
        else:
            url = request.path_url

        return url

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object."""

        conn = self.get_connection(request.url, proxies)

        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)

        chunked = not (request.body is None or 'Content-Length' in request.headers)

        try:
            if not chunked:
                resp = conn.urlopen(
                    method=request.method,
                    url=url,
                    body=request.body,
                    headers=request.headers,
                    redirect=False,
                    assert_same_host=False,
                    preload_content=False,
                    decode_content=False,
                    retries=self.max_retries,
                    timeout=timeout
                )

            # Send the request.
            else:
                if hasattr(conn, 'proxy_pool'):
                    conn = conn.proxy_pool

                low_conn = conn._get_conn(timeout=timeout)
                low_conn.putrequest(request.method, url, skip_accept_encoding=True)

                for header, value in request.headers.items():
                    low_conn.putheader(header, value)

                low_conn.endheaders()

                for i in request.body:
                    low_conn.send(hex(len(i))[2:].encode('utf-8'))
                    low_conn.send(b'\r\n')
                    low_conn.send(i)
                    low_conn.send(b'\r\n')
                low_conn.send(b'0\r\n\r\n')

                r = low_conn.getresponse()
                resp = HTTPResponse.from_httplib(r,
                    pool=conn,
                    connection=low_conn,
                    preload_content=False,
                    decode_content=False
                )

        except socket.error as sockerr:
            raise ConnectionError(sockerr)

        except MaxRetryError as e:
            raise ConnectionError(e)

        except (_SSLError, _HTTPError) as e:
            if isinstance(e, _SSLError):
                raise SSLError(e)
            elif isinstance(e, TimeoutError):
                raise Timeout(e)
            else:
                raise Timeout('Request timed out.')

        r = self.build_response(request, resp)

        if not stream:
            r.content

        return r


class FileAdapter(BaseAdapter):
    def send(self, request, stream=False, verify=None, cert=None, proxies=None, timeout=None):
        # TODO: conditional requests?
        # TODO: idempotent put?
        # TODO: range requests?
        # TODO: logging?
        # TODO: other verbs, OPTIONS, etc.
        # TODO: content-type/encoding negotiation

        if stream:
            raise NotImplementedError("streaming not implemented")

        fname = url_unquote(request.url[len('file://'):])
        response = Response()
        response.url = request.url
        response.headers['Date'] = formatdate(timeval=None, localtime=True)

        try:
            if request.method in ('GET', 'HEAD'):
                statdata = stat(fname)
                etag = '"%s/%s/%s' % (statdata.st_dev, statdata.st_ino, statdata.st_mtime)
                if S_ISLNK(statdata.st_mode):
                    response.status_code = 302
                    response.headers['Status'] = '302 Found'
                    response.headers['Location'] = url_quote('file://' + readlink(fname))
                elif S_ISDIR(statdata.st_mode):
                    response.status_code = 200
                    response.headers['Status'] = '200 Ok'
                    body = """<html><head><title>%s</title></head><body><ul>""" % fname
                    for subfname in sorted(listdir(fname)):
                        body += '<li><a href="file://' + url_quote(subfname) + '">' + \
                                html_escape(fname) + '</a></li>'
                    body += '</body></html>'
                    response.headers['ETag'] = 'W/' + etag
                    response.raw = StringIO(body)
                elif S_ISREG(statdata.st_mode):
                    content = open(fname, 'r').read()
                    response.status_code = 200
                    response.headers['Content-Length'] = statdata.st_size
                    response.headers['Last-Modified'] = formatdate(
                        timeval=statdata.st_mtime,
                        localtime=True
                    )
                    mt, enc = guess_mime_type(request.url, strict=False)
                    if mt is None:
                        mt = 'application/octet-stream'
                    if enc is not None:
                        response.headers['Content-Encoding'] = enc
                    response.headers['Content-Type'] = mt
                    response.headers['ETag'] = etag
                    if request.method == 'GET':
                        response.raw = open(fname, 'r')
                else:
                    response.status_code = 500
                    response.headers['Status'] = '500 Internal Server Error'
            elif request.method == 'PUT':
                 if exists(fname):  # FIXME: Is this right?
                     response.status_code = 409
                     response.headers['Status'] = '409 Conflict'
                 else:
                     open(fname, 'w').write(request.body)
            elif request.method == 'POST':
                 open(fname, 'w').write(request.body)  # FIXME: Is this right?
                 response.status_code = 200
                 response.headers['Status'] = '200 Ok'
            elif request.method == 'DELETE':
                 unlink(fname)
                 response.status_code = 200
                 response.headers['Status'] = '200 Ok'
            else:
                response.status_code = 405
                response.headers['Status'] = '405 Method Not Allowed'
        except OSError, e:
            if e.errno == errno.ENOENT:
               if request.method == 'DELETE':
                   response.status_code = 410
                   response.headers['Status'] = '410 Gone'
               else:
                   response.status_code = 404
                   response.headers['Status'] = '404 Not Found'
            elif e.errno == errno.EISDIR:
               response.status_code = 405
               response.headers['Status'] = '405 Method Not Allowed'
               response.body = 'Cannot %r a directory...' % request.method
            elif e.errno == errno.EACCES:
               response.status_code = 403
               response.headers['Status'] = '403 Forbidden'
            else:
               response.status_code = 500
               response.headers['Status'] = '500 Internal Server Error'
               response.body = 'OSError: ' + strerror(e.errno)
        except Exception:
            response.status_code = 500
            response.headers['500 Internal Server Error']
            response.body = format_exc()

        # context
        response.request = request
        response.connection = self

        # hooks    
        response = dispatch_hook('response', request.hooks, response)

        # streaming
        if not stream:
            response.content

        return response

    def close(self):
        pass
