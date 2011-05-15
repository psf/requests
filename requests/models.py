# -*- coding: utf-8 -*-

"""
requests.system
~~~~~~~~~~~~~~~

"""

import requests
import urllib
import urllib2
import socket
import zlib

from urllib2 import HTTPError
from urlparse import urlparse

from .monkeys import Request as _Request, HTTPBasicAuthHandler, HTTPDigestAuthHandler, HTTPRedirectHandler
from .structures import CaseInsensitiveDict
from .packages.poster.encode import multipart_encode
from .packages.poster.streaminghttp import register_openers, get_handlers



class Request(object):
    """The :class:`Request` object. It carries out all functionality of
    Requests. Recommended interface is with the Requests functions.
    """

    _METHODS = ('GET', 'HEAD', 'PUT', 'POST', 'DELETE')

    def __init__(self, url=None, headers=dict(), files=None, method=None,
                 data=dict(), auth=None, cookiejar=None, timeout=None, redirect=True):

        socket.setdefaulttimeout(timeout)

        self.url = url
        self.headers = headers
        self.files = files
        self.method = method
        self.data = dict()
        self.redirect = redirect

        # self.data = {}
        if hasattr(data, 'items'):
            for (k, v) in data.items():
                self.data.update({
                    k.encode('utf-8') if isinstance(k, unicode) else k:
                    v.encode('utf-8') if isinstance(v, unicode) else v
                })

        # url encode data if it's a dict
        if hasattr(data, 'items'):
            self._enc_data = urllib.urlencode(self.data)
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

        if self.cookiejar is not None:
            _handlers.append(urllib2.HTTPCookieProcessor(self.cookiejar))

        if self.auth:
            if not isinstance(self.auth.handler, (urllib2.AbstractBasicAuthHandler, urllib2.AbstractDigestAuthHandler)):
                auth_manager.add_password(self.auth.realm, self.url, self.auth.username, self.auth.password)
                self.auth.handler = self.auth.handler(auth_manager)
                auth_manager.add_auth(self.url, self.auth)

            _handlers.append(self.auth.handler)


        _handlers.append(HTTPRedirectHandler)
        # print _handlers
        # print '^^'
        # print '!'

        if not _handlers:
            return urllib2.urlopen

        if self.data or self.files:
            _handlers.extend(get_handlers())

        opener = urllib2.build_opener(*_handlers)

        if self.headers:
            # Allow default headers in the opener to be overloaded
            normal_keys = [k.capitalize() for k in self.headers]
            for key, val in opener.addheaders[:]:
                if key not in normal_keys:
                    continue
                # Remove it, we have a value to take its place
                opener.addheaders.remove((key, val))

        return opener.open

    def _build_response(self, resp):
        """Build internal Response object from given response."""

        def build(resp):

            response = Response()
            response.status_code = getattr(resp, 'code', None)

            try:
                response.headers = CaseInsensitiveDict(getattr(resp.info(), 'dict', None))
                response.content = resp.read()
            except AttributeError:
                pass

            if response.headers['content-encoding'] == 'gzip':
                try:
                    response.content = zlib.decompress(response.content, 16+zlib.MAX_WBITS)
                except zlib.error:
                    pass

            response.url = getattr(resp, 'url', None)

            return response


        history = []

        r = build(resp)

        if self.redirect:

            while 'location' in r.headers:

                history.append(r)

                url = r.headers['location']

                request = Request(
                    url, self.headers, self.files, self.method,
                    self.data, self.auth, self.cookiejar, redirect=False
                )
                request.send()
                r = request.response

            r.history = history

        self.response = r


    @staticmethod
    def _build_url(url, data=None):
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
            req.headers.update(self.headers)

        if not self.sent or anyway:

            try:
                opener = self._get_opener()
                resp = opener(req)

                if self.cookiejar is not None:
                    self.cookiejar.extract_cookies(resp, req)

            except urllib2.HTTPError, why:
                self._build_response(why)
                if not self.redirect:
                    self.response.error = why
            else:
                self._build_response(resp)
                self.response.ok = True

            self.response.cached = False
        else:
            self.response.cached = True

        self.sent = self.response.ok

        return self.sent


    def read(self, *args):
        return self.response.read()



class Response(object):
    """The :class:`Request` object. All :class:`Request` objects contain a
    :class:`Request.response <response>` attribute, which is an instance of
    this class.
    """

    def __init__(self):
        self.content = None
        self.status_code = None
        self.headers = CaseInsensitiveDict()
        self.url = None
        self.ok = False
        self.error = None
        self.cached = False
        self.history = []


    def __repr__(self):
        return '<Response [%s]>' % (self.status_code)


    def __nonzero__(self):
        """Returns true if status_code is 'OK'."""
        return not self.error


    def raise_for_status(self):
        """Raises stored HTTPError if one exists."""
        if self.error:
            raise self.error

    def read(self, *args):
        return self.content



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

        # try to make it an AuthObject
        if not isinstance(auth, AuthObject):
            try:
                auth = AuthObject(*auth)
            except TypeError:
                pass

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
        (in_domain, in_path) = self.reduce_uri(uri, False)

        for domain, path, authority in (
            (i[0][0], i[0][1], i[1]) for i in self._auth.iteritems()
        ):
            if in_domain == domain:
                if path in in_path:
                    return authority


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
        'basic': HTTPBasicAuthHandler,
        'digest': HTTPDigestAuthHandler,
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

class RequestException(Exception):
    """There was an ambiguous exception that occured while handling your
    request."""

class AuthenticationError(RequestException):
    """The authentication credentials provided were invalid."""

class URLRequired(RequestException):
    """A valid URL is required to make a request."""

class InvalidMethod(RequestException):
    """An inappropriate method was attempted."""
