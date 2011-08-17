# -*- coding: utf-8 -*-

"""
requests.models
~~~~~~~~~~~~~~~

"""

import urllib
import urllib2
import socket
import zlib

from urllib2 import HTTPError
from urlparse import urlparse, urlunparse, urljoin
from datetime import datetime

from .config import settings
from .monkeys import Request as _Request, HTTPBasicAuthHandler, HTTPForcedBasicAuthHandler, HTTPDigestAuthHandler, HTTPRedirectHandler
from .structures import CaseInsensitiveDict
from .packages.poster.encode import multipart_encode
from .packages.poster.streaminghttp import register_openers, get_handlers
from .utils import dict_from_cookiejar
from .exceptions import RequestException, AuthenticationError, Timeout, URLRequired, InvalidMethod


REDIRECT_STATI = (301, 302, 303, 307)


class Request(object):
    """The :class:`Request <models.Request>` object. It carries out all functionality of
    Requests. Recommended interface is with the Requests functions.
    """

    _METHODS = ('GET', 'HEAD', 'PUT', 'POST', 'DELETE', 'PATCH')

    def __init__(self,
        url=None, headers=dict(), files=None, method=None, data=dict(),
        params=dict(), auth=None, cookiejar=None, timeout=None, redirect=False,
        allow_redirects=False, proxies=None, hooks=None):

        #: Float describ the timeout of the request.
        #  (Use socket.setdefaulttimeout() as fallback)
        self.timeout = timeout

        #: Request URL.
        self.url = url

        #: Dictonary of HTTP Headers to attach to the :class:`Request <models.Request>`.
        self.headers = headers

        #: Dictionary of files to multipart upload (``{filename: content}``).
        self.files = files

        #: HTTP Method to use. Available: GET, HEAD, PUT, POST, DELETE.
        self.method = method

        #: Dictionary or byte of request body data to attach to the
        #: :class:`Request <models.Request>`.
        self.data = None

        #: Dictionary or byte of querystring data to attach to the
        #: :class:`Request <models.Request>`.
        self.params = None

        #: True if :class:`Request <models.Request>` is part of a redirect chain (disables history
        #: and HTTPError storage).
        self.redirect = redirect

        #: Set to True if full redirects are allowed (e.g. re-POST-ing of data at new ``Location``)
        self.allow_redirects = allow_redirects

        # Dictionary mapping protocol to the URL of the proxy (e.g. {'http': 'foo.bar:3128'})
        self.proxies = proxies

        self.data, self._enc_data = self._encode_params(data)
        self.params, self._enc_params = self._encode_params(params)

        #: :class:`Response <models.Response>` instance, containing
        #: content and metadata of HTTP Response, once :attr:`sent <send>`.
        self.response = Response()

        if isinstance(auth, (list, tuple)):
            auth = AuthObject(*auth)
        if not auth:
            auth = auth_manager.get_auth(self.url)

        #: :class:`AuthObject` to attach to :class:`Request <models.Request>`.
        self.auth = auth

        #: CookieJar to attach to :class:`Request <models.Request>`.
        self.cookiejar = cookiejar

        #: True if Request has been sent.
        self.sent = False

        #: Dictionary of event hook callbacks.
        self.hooks = hooks


        # Header manipulation and defaults.

        if settings.accept_gzip:
            settings.base_headers.update({'Accept-Encoding': 'gzip'})

        if headers:
            headers = CaseInsensitiveDict(self.headers)
        else:
            headers = CaseInsensitiveDict()

        for (k, v) in settings.base_headers.items():
            if k not in headers:
                headers[k] = v

        self.headers = headers


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
                # TODO: REMOVE THIS COMPLETELY
                auth_manager.add_password(self.auth.realm, self.url, self.auth.username, self.auth.password)
                self.auth.handler = self.auth.handler(auth_manager)
                auth_manager.add_auth(self.url, self.auth)

            _handlers.append(self.auth.handler)

        if self.proxies:
            _handlers.append(urllib2.ProxyHandler(self.proxies))

        _handlers.append(HTTPRedirectHandler)

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


    def _build_response(self, resp, is_error=False):
        """Build internal :class:`Response <models.Response>` object from given response."""

        def build(resp):

            response = Response()
            response.status_code = getattr(resp, 'code', None)

            try:
                response.headers = CaseInsensitiveDict(getattr(resp.info(), 'dict', None))
                response.read = resp.read
                response.close = resp.close

                if self.cookiejar:

                    response.cookies = dict_from_cookiejar(self.cookiejar)


            except AttributeError:
                pass

            if is_error:
                response.error = resp

            response.url = getattr(resp, 'url', None)

            return response


        history = []

        r = build(resp)

        if r.status_code in REDIRECT_STATI and not self.redirect:

            while (
                ('location' in r.headers) and
                ((self.method in ('GET', 'HEAD')) or
                (r.status_code is 303) or
                (self.allow_redirects))
            ):

                history.append(r)

                url = r.headers['location']

                # Facilitate non-RFC2616-compliant 'location' headers
                # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
                url = urljoin(r.url, url)

                # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.4
                if r.status_code is 303:
                    method = 'GET'
                else:
                    method = self.method

                request = Request(
                    url, self.headers, self.files, method,
                    self.data, self.params, self.auth, self.cookiejar,
                    redirect=True
                )
                request.send()
                r = request.response

            r.history = history

        self.response = r
        self.response.request = self


    @staticmethod
    def _encode_params(data):
        """Encode parameters in a piece of data.

        If the data supplied is a dictionary, encodes each parameter in it, and
        returns a list of tuples containing the encoded parameters, and a urlencoded
        version of that.

        Otherwise, assumes the data is already encoded appropriately, and
        returns it twice.

        """
        if hasattr(data, 'items'):
            result = []
            for k, vs in data.items():
                for v in isinstance(vs, list) and vs or [vs]:
                    result.append((k.encode('utf-8') if isinstance(k, unicode) else k,
                                   v.encode('utf-8') if isinstance(v, unicode) else v))
            return result, urllib.urlencode(result, doseq=True)
        else:
            return data, data


    def _build_url(self):
        """Build the actual URL to use."""

        # Support for unicode domain names.
        parsed_url = list(urlparse(self.url))
        parsed_url[1] = parsed_url[1].encode('idna')
        self.url = urlunparse(parsed_url)

        if self._enc_params:
            if urlparse(self.url).query:
                return '%s&%s' % (self.url, self._enc_params)
            else:
                return '%s?%s' % (self.url, self._enc_params)
        else:
            return self.url


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

        # Logging
        if settings.verbose:
            settings.verbose.write('%s   %s   %s\n' % (
                datetime.now().isoformat(), self.method, self.url
            ))


        url = self._build_url()
        if self.method in ('GET', 'HEAD', 'DELETE'):
            req = _Request(url, method=self.method)
        else:

            if self.files:
                register_openers()

                if self.data:
                    self.files.update(self.data)

                datagen, headers = multipart_encode(self.files)
                req = _Request(url, data=datagen, headers=headers, method=self.method)

            else:
                req = _Request(url, data=self._enc_data, method=self.method)

        if self.headers:
            for k,v in self.headers.iteritems():
                req.add_header(k, v)

        if not self.sent or anyway:

            try:
                opener = self._get_opener()
                try:

                    resp = opener(req, timeout=self.timeout)

                except TypeError, err:
                    # timeout argument is new since Python v2.6
                    if not 'timeout' in str(err):
                        raise

                    if settings.timeout_fallback:
                        # fall-back and use global socket timeout (This is not thread-safe!)
                        old_timeout = socket.getdefaulttimeout()
                        socket.setdefaulttimeout(self.timeout)

                    resp = opener(req)

                    if settings.timeout_fallback:
                        # restore gobal timeout
                        socket.setdefaulttimeout(old_timeout)

                if self.cookiejar is not None:
                    self.cookiejar.extract_cookies(resp, req)

            except (urllib2.HTTPError, urllib2.URLError), why:
                if hasattr(why, 'reason'):
                    if isinstance(why.reason, socket.timeout):
                        why = Timeout(why)

                self._build_response(why, is_error=True)


            else:
                self._build_response(resp)
                self.response.ok = True


        self.sent = self.response.ok

        return self.sent



class Response(object):
    """The core :class:`Response <models.Response>` object. All
    :class:`Request <models.Request>` objects contain a
    :class:`response <models.Response>` attribute, which is an instance
    of this class.
    """

    def __init__(self):
        #: Raw content of the response, in bytes.
        #: If ``content-encoding`` of response was set to ``gzip``, the
        #: response data will be automatically deflated.
        self._content = None
        #: Integer Code of responded HTTP Status.
        self.status_code = None
        #: Case-insensitive Dictionary of Response Headers.
        #: For example, ``headers['content-encoding']`` will return the
        #: value of a ``'Content-Encoding'`` response header.
        self.headers = CaseInsensitiveDict()
        #: Final URL location of Response.
        self.url = None
        #: True if no :attr:`error` occured.
        self.ok = False
        #: Resulting :class:`HTTPError` of request, if one occured.
        self.error = None
        #: A list of :class:`Response <models.Response>` objects from
        #: the history of the Request. Any redirect responses will end
        #: up here.
        self.history = []
        #: The Request that created the Response.
        self.request = None
        self.cookies = None


    def __repr__(self):
        return '<Response [%s]>' % (self.status_code)


    def __nonzero__(self):
        """Returns true if :attr:`status_code` is 'OK'."""
        return not self.error


    def __getattr__(self, name):
        """Read and returns the full stream when accessing to :attr: `content`"""
        if name == 'content':
            if self._content is not None:
                return self._content
            self._content = self.read()
            if self.headers.get('content-encoding', '') == 'gzip':
                try:
                    self._content = zlib.decompress(self._content, 16+zlib.MAX_WBITS)
                except zlib.error:
                    pass
            return self._content


    def raise_for_status(self):
        """Raises stored :class:`HTTPError` or :class:`URLError`, if one occured."""
        if self.error:
            raise self.error


class AuthManager(object):
    """Requests Authentication Manager."""

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
        'forced_basic': HTTPForcedBasicAuthHandler,
        'digest': HTTPDigestAuthHandler,
        'proxy_basic': urllib2.ProxyBasicAuthHandler,
        'proxy_digest': urllib2.ProxyDigestAuthHandler
    }

    def __init__(self, username, password, handler='forced_basic', realm=None):
        self.username = username
        self.password = password
        self.realm = realm

        if isinstance(handler, basestring):
            self.handler = self._handlers.get(handler.lower(), HTTPForcedBasicAuthHandler)
        else:
            self.handler = handler
