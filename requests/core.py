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

from .packages.poster.encode import multipart_encode
from .packages.poster.streaminghttp import register_openers

__all__ = ['Request', 'Response', 'request', 'get', 'head', 'post', 'put', 'delete', 'add_autoauth', 'AUTOAUTHS',
           'RequestException', 'AuthenticationError', 'URLRequired', 'InvalidMethod', 'HTTPError']
__title__ = 'requests'
__version__ = '0.2.5'
__build__ = 0x000205
__author__ = 'Kenneth Reitz'
__license__ = 'ISC'
__copyright__ = 'Copyright 2011 Kenneth Reitz'


AUTOAUTHS = []

class _Request(urllib2.Request):
    """Hidden wrapper around the urllib2.Request object. Allows for manual
    setting of HTTP methods.
    """

    def __init__(self, url, data=None, headers={}, origin_req_host=None,
                 unverifiable=False, method=None):
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

        # url encode data if it's a dict
        if isinstance(data, dict):
            self.data = urllib.urlencode(data)
        else:
            self.data = data

        self.response = Response()

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

        if self.auth or self.cookiejar:
            if self.auth:
                authr = urllib2.HTTPPasswordMgrWithDefaultRealm()

                authr.add_password(None, self.url, self.auth[0], self.auth[1])
                auth_handler = urllib2.HTTPBasicAuthHandler(authr)

                _handlers.append(auth_handler)

            if self.cookiejar:
                cookie_handler = urllib2.HTTPCookieProcessor(cookiejar)
                _handlers.append(cookie_handler)

            opener = urllib2.build_opener(*_handlers)
            return opener.open

        else:
            return urllib2.urlopen


    def _build_response(self, resp):
        """Build internal Response object from given response."""

        self.response.status_code = resp.code
        self.response.headers = resp.info().dict
        self.response.content = resp.read()
        self.response.url = resp.url


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
            req = _Request(("%s?%s" % (self.url, self.data)), method=self.method)
        else:
            if self.files:
                register_openers()
                datagen, headers = multipart_encode(self.files)
                req = _Request(self.url, data=datagen, headers=headers, method=self.method)
            else:
                req = _Request(self.url, method=self.method)

            if self.data:
                req.data = self.data

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
    data = kwargs.pop('data', {}) or kwargs.pop('params', {})

    r = Request(method=method, url=url, data=data, headers=kwargs.pop('headers', {}),
                cookiejar=kwargs.pop('cookies', None), files=kwargs.pop('files', None),
                auth=_detect_auth(url, kwargs.pop('auth', None)))
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

    return request('GET', url, params=params, headers=headers, cookiejar=cookies,
                    auth=_detect_auth(url, auth))


def head(url, params={}, headers={}, cookies=None, auth=None):
    """Sends a HEAD request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of GET Parameters to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    """

    return request('HEAD', url, params=params, headers=headers, cookiejar=cookies,
                    auth=_detect_auth(url, auth))


def post(url, data={}, headers={}, files=None, cookies=None, auth=None):
    """Sends a POST request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary of POST data to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    """

    return request('POST', url, data=data, headers=headers, files=files, cookiejar=cookies,
                    auth=_detect_auth(url, auth))


def put(url, data=b'', headers={}, files={}, cookies=None, auth=None):
    """Sends a PUT request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Bytes of PUT Data to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    """

    return request('PUT', url, data=data, headers=headers, files=files, cookiejar=cookies,
                    auth=_detect_auth(url, auth))


def delete(url, params={}, headers={}, cookies=None, auth=None):
    """Sends a DELETE request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of DELETE Parameters to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    """

    return request('DELETE', url, params=params, headers=headers, cookiejar=cookies,
                    auth=_detect_auth(url, auth))


def add_autoauth(url, authobject):
    """Registers given AuthObject to given URL domain. for auto-activation.
    Once a URL is registered with an AuthObject, the configured HTTP
    Authentication will be used for all requests with URLS containing the given
    URL string.

    Example: ::
        >>> c_auth = requests.AuthObject('kennethreitz', 'xxxxxxx')
        >>> requests.add_autoauth('https://convore.com/api/', c_auth)
        >>> r = requests.get('https://convore.com/api/account/verify.json')
        # Automatically HTTP Authenticated! Wh00t!

    :param url: Base URL for given AuthObject to auto-activate for.
    :param authobject: AuthObject to auto-activate.
    """

    global AUTOAUTHS

    AUTOAUTHS.append((url, authobject))


def _detect_auth(url, auth):
    """Returns registered AuthObject for given url if available, defaulting to
    given AuthObject.
    """

    return _get_autoauth(url) if not auth else auth


def _get_autoauth(url):
    """Returns registered AuthObject for given url if available."""

    for (autoauth_url, auth) in AUTOAUTHS:
        if autoauth_url in url:
            return auth

    return None


class RequestException(Exception):
    """There was an ambiguous exception that occured while handling your
    request."""

class AuthenticationError(RequestException):
    """The authentication credentials provided were invalid."""

class URLRequired(RequestException):
    """A valid URL is required to make a request."""

class InvalidMethod(RequestException):
    """An inappropriate method was attempted."""
