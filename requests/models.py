# -*- coding: utf-8 -*-

"""
requests.models
~~~~~~~~~~~~~~~

This module contains the primary classes that power Requests.
"""

import urllib
import zlib
from Cookie import SimpleCookie
from urlparse import urlparse, urlunparse, urljoin
from weakref import ref

from .packages import urllib3
from .packages.urllib3.filepost import encode_multipart_formdata

from ._config import get_config
from .structures import CaseInsensitiveDict
from .utils import *
from .status_codes import codes
from .exceptions import RequestException, Timeout, URLRequired, TooManyRedirects
from .packages.urllib3.poolmanager import PoolManager


REDIRECT_STATI = (codes.moved, codes.found, codes.other, codes.temporary_moved)


class Request(object):
    """The :class:`Request <Request>` object. It carries out all functionality of
    Requests. Recommended interface is with the Requests functions.
    """

    def __init__(self,
        url=None, headers=dict(), files=None, method=None, data=dict(),
        params=dict(), auth=None, cookies=None, timeout=None, redirect=False,
        allow_redirects=False, proxies=None, config=None, hooks=None,
        _pools=None):

        if cookies is None:
            cookies = {}


        #: Float describ the timeout of the request.
        #  (Use socket.setdefaulttimeout() as fallback)
        self.timeout = timeout

        #: Request URL.
        self.url = url

        #: Dictonary of HTTP Headers to attach to the :class:`Request <Request>`.
        self.headers = headers or {}

        #: Dictionary of files to multipart upload (``{filename: content}``).
        self.files = files or {}

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

        self.config = get_config(config)

        self.data = data
        self._enc_data = encode_params(data)
        self.params = params
        self._enc_params = encode_params(params)

        #: :class:`Response <Response>` instance, containing
        #: content and metadata of HTTP Response, once :attr:`sent <send>`.
        self.response = Response()

        #: :class:`AuthObject` to attach to :class:`Request <Request>`.
        self.auth = auth

        #: CookieJar to attach to :class:`Request <Request>`.
        self.cookies = cookies

        #: True if Request has been sent.
        self.sent = False

        # Header manipulation and defaults.

        if self.config.get('accept_gzip'):
            self.headers.update({'Accept-Encoding': 'gzip'})

        if headers:
            headers = CaseInsensitiveDict(self.headers)
        else:
            headers = CaseInsensitiveDict()

        for (k, v) in self.config.get('base_headers').items():
            if k not in headers:
                headers[k] = v

        self.headers = headers

        self.hooks = hooks
        self._pools = _pools

    def __repr__(self):
        return '<Request [%s]>' % (self.method)

    def _checks(self):
        """Deterministic checks for consistency."""

        if not self.url:
            raise URLRequired

    def _build_response(self, resp, is_error=False):
        """Build internal :class:`Response <Response>` object
        from given response.
        """

        def build(resp):

            response = Response()

            # Pass settings over.
            response.config = self.config

            # Fallback to None if there's no staus_code, for whatever reason.
            response.status_code = getattr(resp, 'status', None)

            # Make headers case-insensitive.
            response.headers = CaseInsensitiveDict(getattr(resp, 'headers', None))

            # Start off with our local cookies.
            cookies = self.cookies or dict()

            # Add new cookies from the server.
            if 'set-cookie' in response.headers:
                cookie_header = response.headers['set-cookie']

                c = SimpleCookie()
                c.load(cookie_header)

                for k,v in c.items():
                    cookies.update({k: v.value})

            # Save cookies in Response.
            response.cookies = cookies

            # Save original resopnse for later.
            response.raw = resp

            # TODO: ?
            if is_error:
                response.error = resp

            return response

        # Request collector.
        history = []

        # Create the lone response object.
        r = build(resp)
        self.cookies.update(r.cookies)

        # Store the HTTP response, just in case.
        r._response = resp

        # It's a redirect, and we're not already in a redirect loop.
        if r.status_code in REDIRECT_STATI and not self.redirect:

            while (
                # There's a `Location` header.
                ('location' in r.headers) and

                # See other response.
                ((r.status_code is codes.see_other) or

                # Opt-in to redirects for non- idempotent methods.
                (self.allow_redirects))
            ):

                # We already redirected. Don't keep it alive.
                # r.raw.close()

                # Woah, this is getting crazy.
                if len(history) >= self.config.get('max_redirects'):
                    raise TooManyRedirects()

                # Add the old request to the history collector.
                history.append(r)

                url = cleanup_url(r.headers['location'], parent_url=self.url)

                # If 303, convert to idempotent GET.
                # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.4
                if r.status_code is codes.see_other:
                    method = 'GET'
                else:
                    method = self.method

                # Create the new Request.
                request = Request(
                    url=url,
                    headers=self.headers,
                    files=self.files,
                    method=method,
                    data=self.data,
                    # params=self.params,
                    params=None,
                    auth=self.auth,
                    cookies=self.cookies,
                    _pools=self._pools,
                    config=self.config,

                    # Flag as part of a redirect loop.
                    redirect=True
                )

                # Send her away!
                request.send()
                r = request.response

                self.cookies.update(r.cookies or {})

            # Insert collected history.
            r.history = history

        # Attach Response to Request.
        self.response = r

        # Give Response some context.
        self.response.request = self


    def send(self, anyway=False):
        """Sends the HTTP Request. Populates `Request.response`.

        Returns True if everything went according to plan.
        """

        # Safety check.
        self._checks()

        # Build the final URL.
        url = build_url(self.url, self.params)

        # Nottin' on you.
        body = None
        content_type = None

        # Multi-part file uploads.
        if self.files:
            if not isinstance(self.data, basestring):
                fields = self.data.copy()
                for (k, v) in self.files.items():
                    fields.update({k: (k, v.read())})
                (body, content_type) = encode_multipart_formdata(fields)

        # Setup form data.
        if self.data and (not body):
            if isinstance(self.data, basestring):
                body = self.data
            else:
                body = encode_params(self.data)
                content_type = 'application/x-www-form-urlencoded'

        # Setup cookies.

        # Add content-type if it wasn't explicitly provided.
        if (content_type) and (not 'content-type' in self.headers):
            self.headers['Content-Type'] = content_type

        # Only send the Request if new or forced.
        if (anyway) or (not self.sent):

            try:
                # Create a new HTTP connection, since one wasn't passed in.
                if not self._pools:

                    # Create a pool manager for this one connection.
                    pools = PoolManager(
                        num_pools=self.config.get('max_connections'),
                        maxsize=1,
                        timeout=self.timeout
                    )

                    # Create a connection.
                    connection = pools.connection_from_url(url)

                    # One-off request. Delay fetching the content until needed.
                    do_block = False
                else:
                    # Create a connection.
                    connection = self._pools.connection_from_url(url)

                    # Syntax sugar.
                    pools = self._pools

                    # Part of a connection pool, so no fancy stuff. Sorry!
                    do_block = False

                if self.cookies:
                    # Skip if 'cookie' header is explicitly set.
                    if 'cookie' not in self.headers:

                        # Simple cookie with our dict.
                        c = SimpleCookie()
                        c.load(self.cookies)

                        # Turn it into a header.
                        cookie_header = c.output(header='').strip()

                        # Attach Cookie header to request.
                        self.headers['Cookie'] = cookie_header

                # Create the connection.
                r = connection.urlopen(
                    method=self.method,
                    url=url,
                    body=body,
                    headers=self.headers,
                    redirect=False,
                    assert_same_host=False,
                    preload_content=do_block,
                    decode_content=False
                )

                # Set the pools manager for redirections, if allowed.
                if self.config.get('keep_alive') and pools:
                    self._pools = pools


            # except (urllib2.HTTPError, urllib2.URLError), why:
            except Exception, why:
                print why.__dict__
                # if hasattr(why, 'reason'):
                #     if isinstance(why.reason, socket.timeout):
                #         why = Timeout(why)

                # self._build_response(why, is_error=True)
                print 'FUCK'
                print why

            else:
                # self.response = Response.from_urllib3()
                self._build_response(r)
                self.response.ok = True

        self.sent = self.response.ok

        return self.sent


class Response(object):
    """The core :class:`Response <Response>` object.


    All :class:`Request <Request>` objects contain a :class:`response
    <Response>` attribute, which is an instance of this class.
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

        #: True if no :attr:`error` occured.
        self.ok = False

        #: Resulting :class:`HTTPError` of request, if one occured.
        self.error = None

        #: A list of :class:`Response <Response>` objects from
        #: the history of the Request. Any redirect responses will end
        #: up here.
        self.history = []

        #: The :class:`Request <Request>` that created the Response.
        self.request = None

        #: A dictionary of Cookies the server sent back.
        self.cookies = None

        #: A dictionary of configuration.
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
        gen = generate

        if 'gzip' in self.headers.get('content-encoding', ''):
            gen = stream_decode_gzip(gen)

        if decode_unicode is None:
            decode_unicode = settings.decode_unicode

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
            raise RuntimeError(
                'The content for this response was already consumed')

        # Read the contents.
        self._content = self.raw.read() or self.raw.data

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
        """Raises stored :class:`HTTPError` or :class:`URLError`,
        if one occured.
        """

        if self.error:
            raise self.error

        if (self.status_code >= 300) and (self.status_code < 400):
            raise Exception('300 yo')

        elif (self.status_code >= 400) and (self.status_code < 500):
            raise Exception('400 yo')

        elif (self.status_code >= 500) and (self.status_code < 600):
            raise Exception('500 yo')
