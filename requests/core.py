# -*- coding: utf-8 -*-

"""
    requests.core
    ~~~~~~~~~~~~~

    This module implements the main Requests system.

    :copyright: (c) 2011 by Kenneth Reitz.
    :license: ISC, see LICENSE for more details.
"""

from __future__ import absolute_import

import urllib
import urllib2

from urllib2 import HTTPError
from urlparse import urlparse

from .packages.poster.encode import multipart_encode
from .packages.poster.streaminghttp import register_openers, get_handlers



__title__ = 'requests'
__version__ = '0.3.0'
__build__ = 0x000300
__author__ = 'Kenneth Reitz'
__license__ = 'ISC'
__copyright__ = 'Copyright 2011 Kenneth Reitz'

__all__ = [
    'Request', 'Response', 'request', 'get', 'head', 'post', 'put', 'delete', 
    'auth_manager', 'AuthObject','RequestException', 'AuthenticationError', 
    'URLRequired', 'InvalidMethod', 'HTTPError'
]



class _Request(urllib2.Request):
    """Hidden wrapper around the urllib2.Request object. Allows for manual
    setting of HTTP methods.
    """

    def __init__(self, url, data=None, headers={}, origin_req_host=None, unverifiable=False, method=None):
        urllib2.Request.__init__(self, url, data, headers, origin_req_host, unverifiable)
        self.method = method

    def get_method(self):
        if self.method:
            return self.method

        return urllib2.Request.get_method(self)


class Request(object):
    """The :class:`Request` object. It carries out all functionality of
    Requests. Recommended interface is with the Requests functions.
    """

    _METHODS = ('GET', 'HEAD', 'PUT', 'POST', 'DELETE')

    def __init__(self, url=None, headers=dict(), files=None, method=None,
                 data=dict(), auth=None, cookiejar=None):
        
        self.url = url
        self.headers = headers
        self.files = files
        self.method = method
        self.data = data

        # url encode data if it's a dict
        if hasattr(data, 'items'):
            self._enc_data = urllib.urlencode(data)
        else:
            self._enc_data = data

        self.response = Response()

        if isinstance(auth, (list, tuple)):
            auth = AuthObject(*auth)
        if not auth:
            auth = auth_manager.get_auth(self.url)
        self.auth = auth
        self.cookiejar = cookiejar
        self.sent = False


    def __repr__(self):
        return '<Request [%s]>' % (self.method)


    def __setattr__(self, name, value):
        if (name == 'method') and (value):
            if not value in self._METHODS:
                raise InvalidMethod()

        object.__setattr__(self, name, value)


    def _checks(self):
        """Deterministic checks for consistency."""

        if not self.url:
            raise URLRequired


    def _get_opener(self):
        """Creates appropriate opener object for urllib2."""

        _handlers = []

        if self.auth:
            if not isinstance(self.auth.handler, (urllib2.AbstractBasicAuthHandler, urllib2.AbstractDigestAuthHandler)):
                auth_manager.add_password(self.auth.realm, self.url, self.auth.username, self.auth.password)
                self.auth.handler = self.auth.handler(auth_manager)
                auth_manager.add_auth(self.url, self.auth)

            _handlers.append(self.auth.handler)

            _handlers.extend(get_handlers())
            opener = urllib2.build_opener(*_handlers)
            return opener.open
        else:
            return urllib2.urlopen


    def _build_response(self, resp):
        """Build internal Response object from given response."""
        
        self.response.status_code = getattr(resp, 'code', None)
        self.response.headers = getattr(resp.info(), 'dict', None)
        self.response.url = getattr(resp, 'url', None)
        self.response.content = resp.read()


    @staticmethod
    def _build_url(url, data):
        """Build URLs."""
        
        if urlparse(url).query:
            return '%s&%s' % (url, data)
        else:
            if data:
                return '%s?%s' % (url, data)
            else:
                return url


    def send(self, anyway=False):
        """Sends the request. Returns True of successful, false if not.
        If there was an HTTPError during transmission,
        self.response.status_code will contain the HTTPError code.

        Once a request is successfully sent, `sent` will equal True.

        :param anyway: If True, request will be sent, even if it has
        already been sent.
        """
        self._checks()
        success = False

        if self.method in ('GET', 'HEAD', 'DELETE'):
            req = _Request(self._build_url(self.url, self._enc_data), method=self.method)
        else:

            if self.files:
                register_openers()

                if self.data:
                    self.files.update(self.data)
                    
                datagen, headers = multipart_encode(self.files)
                req = _Request(self.url, data=datagen, headers=headers, method=self.method)
                
            else:
                req = _Request(self.url, data=self._enc_data, method=self.method)

        if self.headers:
            req.headers = self.headers

        if not self.sent or anyway:
            try:
                opener = self._get_opener()
                resp =  opener(req)
            except urllib2.HTTPError, why:
                self._build_response(why)
                self.response.error = why
            else:
                self._build_response(resp)
                self.response.ok = True

            self.response.cached = False
        else:
            self.response.cached = True


        self.sent = self.response.ok

        return self.sent


    
class Response(object):
    """The :class:`Request` object. All :class:`Request` objects contain a
    :class:`Request.response <response>` attribute, which is an instance of
    this class.
    """

    def __init__(self):
        self.content = None
        self.status_code = None
        self.headers = dict()
        self.url = None
        self.ok = False
        self.error = None
        self.cached = False


    def __repr__(self):
        return '<Response [%s]>' % (self.status_code)


    def __nonzero__(self):
        """Returns true if status_code is 'OK'."""
        return not self.error


    def raise_for_status(self):
        """Raises stored HTTPError if one exists."""
        if self.error:
            raise self.error



class AuthManager(object):
    """Authentication Manager."""
    
    def __new__(cls):
        singleton = cls.__dict__.get('__singleton__')
        if singleton is not None:
            return singleton

        cls.__singleton__ = singleton = object.__new__(cls)

        return singleton


    def __init__(self):
        self.passwd = {}
        self._auth = {}


    def __repr__(self):
        return '<AuthManager [%s]>' % (self.method)


    def add_auth(self, uri, auth):
        """Registers AuthObject to AuthManager."""
        
        uri = self.reduce_uri(uri, False)
        self._auth[uri] = auth

    def add_password(self, realm, uri, user, passwd):
        """Adds password to AuthManager."""
        # uri could be a single URI or a sequence
        if isinstance(uri, basestring):
            uri = [uri]
            
        reduced_uri = tuple([self.reduce_uri(u, False) for u in uri])
        
        if reduced_uri not in self.passwd:
            self.passwd[reduced_uri] = {}
        self.passwd[reduced_uri] = (user, passwd)


    def find_user_password(self, realm, authuri):
        for uris, authinfo in self.passwd.iteritems():
            reduced_authuri = self.reduce_uri(authuri, False)
            for uri in uris:
                if self.is_suburi(uri, reduced_authuri):
                    return authinfo

        return (None, None)


    def get_auth(self, uri):
        uri = self.reduce_uri(uri, False)
        return self._auth.get(uri, None)


    def reduce_uri(self, uri, default_port=True):
        """Accept authority or URI and extract only the authority and path."""
        # note HTTP URLs do not have a userinfo component
        parts = urllib2.urlparse.urlsplit(uri)
        if parts[1]:
            # URI
            scheme = parts[0]
            authority = parts[1]
            path = parts[2] or '/'
        else:
            # host or host:port
            scheme = None
            authority = uri
            path = '/'
        host, port = urllib2.splitport(authority)
        if default_port and port is None and scheme is not None:
            dport = {"http": 80,
                     "https": 443,
                     }.get(scheme)
            if dport is not None:
                authority = "%s:%d" % (host, dport)
        return authority, path

    
    def is_suburi(self, base, test):
        """Check if test is below base in a URI tree

        Both args must be URIs in reduced form.
        """
        if base == test:
            return True
        if base[0] != test[0]:
            return False
        common = urllib2.posixpath.commonprefix((base[1], test[1]))
        if len(common) == len(base[1]):
            return True
        return False


    def empty(self):
        self.passwd = {}


    def remove(self, uri, realm=None):
        # uri could be a single URI or a sequence
        if isinstance(uri, basestring):
            uri = [uri]

        for default_port in True, False:
            reduced_uri = tuple([self.reduce_uri(u, default_port) for u in uri])
            del self.passwd[reduced_uri][realm]


    def __contains__(self, uri):
        # uri could be a single URI or a sequence
        if isinstance(uri, basestring):
            uri = [uri]

        uri = tuple([self.reduce_uri(u, False) for u in uri])

        if uri in self.passwd:
            return True

        return False

auth_manager = AuthManager()



class AuthObject(object):
    """The :class:`AuthObject` is a simple HTTP Authentication token. When
    given to a Requests function, it enables Basic HTTP Authentication for that
    Request. You can also enable Authorization for domain realms with AutoAuth.
    See AutoAuth for more details.

    :param username: Username to authenticate with.
    :param password: Password for given username.
    :param realm: (optional) the realm this auth applies to
    :param handler: (optional) basic || digest || proxy_basic || proxy_digest
    """

    _handlers = {
        'basic': urllib2.HTTPBasicAuthHandler,
        'digest': urllib2.HTTPDigestAuthHandler,
        'proxy_basic': urllib2.ProxyBasicAuthHandler,
        'proxy_digest': urllib2.ProxyDigestAuthHandler
    }

    def __init__(self, username, password, handler='basic', realm=None):
        self.username = username
        self.password = password
        self.realm = realm

        if isinstance(handler, basestring):
            self.handler = self._handlers.get(handler.lower(), urllib2.HTTPBasicAuthHandler)
        else:
            self.handler = handler




def request(method, url, **kwargs):
    """Sends a `method` request. Returns :class:`Response` object.

    :param method: method for the new :class:`Request` object.
    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of GET/HEAD/DELETE Parameters to send with the :class:`Request`.
    :param data: (optional) Bytes/Dictionary of PUT/POST Data to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    """
    data = kwargs.pop('data', dict()) or kwargs.pop('params', dict())

    r = Request(method=method, url=url, data=data, headers=kwargs.pop('headers', {}),
                cookiejar=kwargs.pop('cookies', None), files=kwargs.pop('files', None),
                auth=kwargs.pop('auth', auth_manager.get_auth(url)))
    r.send()

    return r.response


def get(url, params={}, headers={}, cookies=None, auth=None):
    """Sends a GET request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of GET Parameters to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    """
    
    return request('GET', url, params=params, headers=headers, cookiejar=cookies, auth=auth)


def head(url, params={}, headers={}, cookies=None, auth=None):
    """Sends a HEAD request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of GET Parameters to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    """

    return request('HEAD', url, params=params, headers=headers, cookiejar=cookies, auth=auth)


def post(url, data={}, headers={}, files=None, cookies=None, auth=None):
    """Sends a POST request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary of POST data to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    """

    return request('POST', url, data=data, headers=headers, files=files, cookiejar=cookies, auth=auth)


def put(url, data='', headers={}, files={}, cookies=None, auth=None):
    """Sends a PUT request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Bytes of PUT Data to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    """

    return request('PUT', url, data=data, headers=headers, files=files, cookiejar=cookies, auth=auth)


def delete(url, params={}, headers={}, cookies=None, auth=None):
    """Sends a DELETE request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of DELETE Parameters to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    """

    return request('DELETE', url, params=params, headers=headers, cookiejar=cookies, auth=auth)



class RequestException(Exception):
    """There was an ambiguous exception that occured while handling your
    request."""

class AuthenticationError(RequestException):
    """The authentication credentials provided were invalid."""

class URLRequired(RequestException):
    """A valid URL is required to make a request."""

class InvalidMethod(RequestException):
    """An inappropriate method was attempted."""
