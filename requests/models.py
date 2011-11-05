
# -*- coding: utf-8 -*-

"""
requests.models
~~~~~~~~~~~~~~~

"""

import urllib
import urllib2
import socket
import zlib

from urlparse import urlparse, urlunparse, urljoin
from datetime import datetime

from .auth import dispatch as auth_dispatch
from .hooks import dispatch_hook
from .structures import CaseInsensitiveDict
from .packages.poster.encode import multipart_encode
from .packages.poster.streaminghttp import register_openers, get_handlers
from .status_codes import codes
from .exceptions import Timeout, URLRequired, TooManyRedirects
from .monkeys import Request as _Request
from .monkeys import HTTPRedirectHandler
from .utils import (
    dict_from_cookiejar, get_unicode_from_response,
    stream_decode_response_unicode, decode_gzip, stream_decode_gzip)


REDIRECT_STATI = (codes.moved, codes.found, codes.other, codes.temporary_moved)



class Request(object):
    """The :class:`Request <Request>` object. It carries out all functionality of
    Requests. Recommended interface is with the Requests functions.
    """

    def __init__(self,
        url=None,
        headers=dict(),
        files=None,
        method=None,
        data=dict(),
        params=dict(),
        auth=None,
        cookies=None,
        timeout=None,
        redirect=False,
        allow_redirects=False,
        proxies=None,
        hooks=None,
        config=None):

        #: Float describes the timeout of the request.
        #  (Use socket.setdefaulttimeout() as fallback)
        self.timeout = timeout

        #: Request URL.
        self.url = url

        #: Dictionary of HTTP Headers to attach to the :class:`Request <Request>`.
        self.headers = headers

        #: Dictionary of files to multipart upload (``{filename: content}``).
        self.files = files

        #: HTTP Method to use.
        self.method = method

        #: Dictionary or byte of request body data to attach to the
        #: :class:`Request <Request>`.
        self.data = None

        #: Dictionary or byte of querystring data to attach to the
        #: :class:`Request <Request>`.
        self.params = None

        #: True if :class:`Request <Request>` is part of a redirect chain (disables history
        #: and HTTPError storage).
        self.redirect = redirect

        #: Set to True if full redirects are allowed (e.g. re-POST-ing of data at new ``Location``)
        self.allow_redirects = allow_redirects

        # Dictionary mapping protocol to the URL of the proxy (e.g. {'http': 'foo.bar:3128'})
        self.proxies = proxies

        self.data, self._enc_data = self._encode_params(data)
        self.params, self._enc_params = self._encode_params(params)

        #: :class:`Response <Response>` instance, containing
        #: content and metadata of HTTP Response, once :attr:`sent <send>`.
        self.response = Response()

        #: Authentication tuple to attach to :class:`Request <Request>`.
        self._auth = auth
        self.auth = auth_dispatch(auth)

        #: CookieJar to attach to :class:`Request <Request>`.
        self.cookies = cookies

        #: Dictionary of configurations for this request.
        self.config = config

        #: True if Request has been sent.
        self.sent = False

        #: Event-handling hooks.
        self.hooks = hooks

        if headers:
            headers = CaseInsensitiveDict(self.headers)
        else:
            headers = CaseInsensitiveDict()

        for (k, v) in self.config.get('base_headers', {}).items():
            if k not in headers:
                headers[k] = v

        self.headers = headers

        # Pre-request hook.
        r = dispatch_hook('pre_request', hooks, self)
        self.__dict__.update(r.__dict__)


    def __repr__(self):
        return '<Request [%s]>' % (self.method)


    def _get_opener(self):
        """Creates appropriate opener object for urllib2."""

        _handlers = []

        if self.cookies is not None:
            _handlers.append(urllib2.HTTPCookieProcessor(self.cookies))

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
        """Build internal :class:`Response <Response>` object
        from given response.
        """


        def build(resp):

            response = Response()
            response.config = self.config
            response.status_code = getattr(resp, 'code', None)

            try:
                response.headers = CaseInsensitiveDict(getattr(resp.info(), 'dict', None))
                response.raw = resp

                if self.cookies:
                    response.cookies = dict_from_cookiejar(self.cookies)


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
                ((r.status_code is codes.see_other) or (self.allow_redirects))
            ):

                r.raw.close()

                if not len(history) < self.config.get('max_redirects'):
                    raise TooManyRedirects()

                history.append(r)

                url = r.headers['location']

                # Handle redirection without scheme (see: RFC 1808 Section 4)
                if url.startswith('//'):
                    parsed_rurl = urlparse(r.url)
                    url = '%s:%s' % (parsed_rurl.scheme, url)

                # Facilitate non-RFC2616-compliant 'location' headers
                # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
                if not urlparse(url).netloc:
                    url = urljoin(r.url, urllib.quote(urllib.unquote(url)))

                # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.4
                if r.status_code is codes.see_other:
                    method = 'GET'
                else:
                    method = self.method

                request = Request(
                    url=url,
                    headers=self.headers,
                    files=self.files,
                    method=method,
                    # data=self.data,
                    # params=self.params,
                    auth=self._auth,
                    cookies=self.cookies,
                    redirect=True,
                    config=self.config
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

        # Support for unicode domain names and paths.
        scheme, netloc, path, params, query, fragment = urlparse(self.url)
        netloc = netloc.encode('idna')
        if isinstance(path, unicode):
            path = path.encode('utf-8')
        path = urllib.quote(urllib.unquote(path))
        self.url = str(urlunparse([ scheme, netloc, path, params, query, fragment ]))

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

        # Some people...
        if not self.url:
            raise URLRequired

        # Logging
        if self.config.get('verbose'):
            self.config.get('verbose').write('%s   %s   %s\n' % (
                datetime.now().isoformat(), self.method, self.url
            ))

        # Build the URL
        url = self._build_url()

        # Attach uploaded files.
        if self.files:
            register_openers()

            # Add form-data to the multipart.
            if self.data:
                self.files.update(self.data)

            data, headers = multipart_encode(self.files)

        else:
            data = self._enc_data
            headers = {}

        if self.auth:
            auth_func, auth_args = self.auth

            r = auth_func(self, *auth_args)

            self.__dict__.update(r.__dict__)

        # Build the Urllib2 Request.
        req = _Request(url, data=data, headers=headers, method=self.method)

        # Add the headers to the request.
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

                    if self.config.get('timeout_fallback'):
                        # fall-back and use global socket timeout (This is not thread-safe!)
                        old_timeout = socket.getdefaulttimeout()
                        socket.setdefaulttimeout(self.timeout)

                    resp = opener(req)

                    if self.config.get('timeout_fallback'):
                        # restore global timeout
                        socket.setdefaulttimeout(old_timeout)

                if self.cookies is not None:
                    self.cookies.extract_cookies(resp, req)

            except (urllib2.HTTPError, urllib2.URLError), why:
                if hasattr(why, 'reason'):
                    if isinstance(why.reason, socket.timeout):
                        why = Timeout(why)
                    elif isinstance(why.reason, socket.error):
                        why = Timeout(why)

                self._build_response(why, is_error=True)

            else:
                self._build_response(resp)
                self.response.ok = True


        self.sent = self.response.ok

        # Response manipulation hook.
        self.response = dispatch_hook('response', self.hooks, self.response)

        # Post-request hook.
        r = dispatch_hook('post_request', self.hooks, self)
        self.__dict__.update(r.__dict__)

        return self.sent


class Response(object):
    """The core :class:`Response <Response>` object. All
    :class:`Request <Request>` objects contain a
    :class:`response <Response>` attribute, which is an instance
    of this class.
    """

    def __init__(self):

        self._content = None
        self._content_consumed = False

        #: Integer Code of responded HTTP Status.
        self.status_code = None

        #: Case-insensitive Dictionary of Response Headers.
        #: For example, ``headers['content-encoding']`` will return the
        #: value of a ``'Content-Encoding'`` response header.
        self.headers = CaseInsensitiveDict()

        #: File-like object representation of response (for advanced usage).
        self.raw = None

        #: Final URL location of Response.
        self.url = None

        #: True if no :attr:`error` occurred.
        self.ok = False

        #: Resulting :class:`HTTPError` of request, if one occurred.
        self.error = None

        #: A list of :class:`Response <Response>` objects from
        #: the history of the Request. Any redirect responses will end
        #: up here.
        self.history = []

        #: The :class:`Request <Request>` that created the Response.
        self.request = None

        #: A dictionary of Cookies the server sent back.
        self.cookies = None

        #: Dictionary of configurations for this request.
        self.config = None


    def __repr__(self):
        return '<Response [%s]>' % (self.status_code)


    def __nonzero__(self):
        """Returns true if :attr:`status_code` is 'OK'."""

        return not self.error

    def iter_content(self, chunk_size=10 * 1024, decode_unicode=None):
        """Iterates over the response data.  This avoids reading the content
        at once into memory for large responses.  The chunk size is the number
        of bytes it should read into memory.  This is not necessarily the
        length of each item returned as decoding can take place.
        """
        if self._content_consumed:
            raise RuntimeError('The content for this response was '
                               'already consumed')

        def generate():
            while 1:
                chunk = self.raw.read(chunk_size)
                if not chunk:
                    break
                yield chunk
            self._content_consumed = True
        gen = generate()
        if 'gzip' in self.headers.get('content-encoding', ''):
            gen = stream_decode_gzip(gen)
        if decode_unicode is None:
            decode_unicode = self.config.get('decode_unicode')
        if decode_unicode:
            gen = stream_decode_response_unicode(gen, self)
        return gen

    @property
    def content(self):
        """Content of the response, in bytes or unicode
        (if available).
        """

        if self._content is not None:
            return self._content

        if self._content_consumed:
            raise RuntimeError('The content for this response was '
                               'already consumed')

        # Read the contents.
        try:
            self._content = self.raw.read()
        except AttributeError:
            return None


        # Decode GZip'd content.
        if 'gzip' in self.headers.get('content-encoding', ''):
            try:
                self._content = decode_gzip(self._content)
            except zlib.error:
                pass

        # Decode unicode content.
        if self.config.get('decode_unicode'):
            self._content = get_unicode_from_response(self)

        self._content_consumed = True
        return self._content


    def raise_for_status(self):
        """Raises stored :class:`HTTPError` or :class:`URLError`, if one occurred."""
        if self.error:
            raise self.error

