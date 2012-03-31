# -*- coding: utf-8 -*-

"""
requests.models
~~~~~~~~~~~~~~~

This module contains the primary objects that power Requests.
"""

import os
from datetime import datetime

from .hooks import dispatch_hook, HOOKS
from .structures import CaseInsensitiveDict
from .status_codes import codes

from .auth import HTTPBasicAuth, HTTPProxyAuth
from .packages.urllib3.response import HTTPResponse
from .packages.urllib3.exceptions import MaxRetryError
from .packages.urllib3.exceptions import SSLError as _SSLError
from .packages.urllib3.exceptions import HTTPError as _HTTPError
from .packages.urllib3 import connectionpool, poolmanager
from .packages.urllib3.filepost import encode_multipart_formdata
from .defaults import SCHEMAS
from .exceptions import (
    ConnectionError, HTTPError, RequestException, Timeout, TooManyRedirects,
    URLRequired, SSLError, MissingSchema, InvalidSchema)
from .utils import (
    get_encoding_from_headers, stream_untransfer, guess_filename, requote_uri,
    dict_from_string, stream_decode_response_unicode, get_netrc_auth)
from .compat import (
    urlparse, urlunparse, urljoin, urlsplit, urlencode, str, bytes,
    SimpleCookie, is_py2)

# Import chardet if it is available.
try:
    import chardet
except ImportError:
    pass

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
        config=None,
        _poolmanager=None,
        verify=None,
        session=None,
        cert=None):

        #: Dictionary of configurations for this request.
        self.config = dict(config or [])

        #: Float describes the timeout of the request.
        #  (Use socket.setdefaulttimeout() as fallback)
        self.timeout = timeout

        #: Request URL.
        self.url = url

        #: Dictionary of HTTP Headers to attach to the :class:`Request <Request>`.
        self.headers = dict(headers or [])

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
        self.proxies = dict(proxies or [])

        # If no proxies are given, allow configuration by environment variables
        # HTTP_PROXY and HTTPS_PROXY.
        if not self.proxies and self.config.get('trust_env'):
          if 'HTTP_PROXY' in os.environ:
            self.proxies['http'] = os.environ['HTTP_PROXY']
          if 'HTTPS_PROXY' in os.environ:
            self.proxies['https'] = os.environ['HTTPS_PROXY']

        self.data, self._enc_data = self._encode_params(data)
        self.params, self._enc_params = self._encode_params(params)

        #: :class:`Response <Response>` instance, containing
        #: content and metadata of HTTP Response, once :attr:`sent <send>`.
        self.response = Response()

        #: Authentication tuple or object to attach to :class:`Request <Request>`.
        self.auth = auth

        #: CookieJar to attach to :class:`Request <Request>`.
        self.cookies = dict(cookies or [])

        #: True if Request has been sent.
        self.sent = False

        #: Event-handling hooks.
        self.hooks = {}

        for event in HOOKS:
            self.hooks[event] = []

        hooks = hooks or {}

        for (k, v) in list(hooks.items()):
            self.register_hook(event=k, hook=v)

        #: Session.
        self.session = session

        #: SSL Verification.
        self.verify = verify

        #: SSL Certificate
        self.cert = cert

        if headers:
            headers = CaseInsensitiveDict(self.headers)
        else:
            headers = CaseInsensitiveDict()

        # Add configured base headers.
        for (k, v) in list(self.config.get('base_headers', {}).items()):
            if k not in headers:
                headers[k] = v

        self.headers = headers
        self._poolmanager = _poolmanager

    def __repr__(self):
        return '<Request [%s]>' % (self.method)

    def _build_response(self, resp):
        """Build internal :class:`Response <Response>` object
        from given response.
        """

        def build(resp):

            response = Response()

            # Pass settings over.
            response.config = self.config

            if resp:

                # Fallback to None if there's no status_code, for whatever reason.
                response.status_code = getattr(resp, 'status', None)

                # Make headers case-insensitive.
                response.headers = CaseInsensitiveDict(getattr(resp, 'headers', None))

                # Set encoding.
                response.encoding = get_encoding_from_headers(response.headers)

                # Start off with our local cookies.
                cookies = self.cookies or dict()

                # Add new cookies from the server.
                if 'set-cookie' in response.headers:
                    cookie_header = response.headers['set-cookie']
                    cookies = dict_from_string(cookie_header)

                # Save cookies in Response.
                response.cookies = cookies

                # No exceptions were harmed in the making of this request.
                response.error = getattr(resp, 'error', None)

            # Save original response for later.
            response.raw = resp
            if isinstance(self.full_url, bytes):
                response.url = self.full_url.decode('utf-8')
            else:
                response.url = self.full_url

            return response

        history = []

        r = build(resp)

        self.cookies.update(r.cookies)

        if r.status_code in REDIRECT_STATI and not self.redirect:

            while (('location' in r.headers) and
                   ((r.status_code is codes.see_other) or (self.allow_redirects))):

                r.content  # Consume socket so it can be released

                if not len(history) < self.config.get('max_redirects'):
                    raise TooManyRedirects()

                # Release the connection back into the pool.
                r.raw.release_conn()

                history.append(r)

                url = r.headers['location']
                data = self.data

                # Handle redirection without scheme (see: RFC 1808 Section 4)
                if url.startswith('//'):
                    parsed_rurl = urlparse(r.url)
                    url = '%s:%s' % (parsed_rurl.scheme, url)

                # Facilitate non-RFC2616-compliant 'location' headers
                # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
                if not urlparse(url).netloc:
                    url = urljoin(r.url,
                                  # Compliant with RFC3986, we percent
                                  # encode the url.
                                  requote_uri(url))

                # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.4
                if r.status_code is codes.see_other:
                    method = 'GET'
                    data = None
                else:
                    method = self.method

                # Do what the browsers do if strict_mode is off...
                if (not self.config.get('strict_mode')):

                    if r.status_code in (codes.moved, codes.found) and self.method == 'POST':
                        method = 'GET'
                        data = None

                    if (r.status_code == 303) and self.method != 'HEAD':
                        method = 'GET'
                        data = None

                # Remove the cookie headers that were sent.
                headers = self.headers
                try:
                    del headers['Cookie']
                except KeyError:
                    pass

                request = Request(
                    url=url,
                    headers=headers,
                    files=self.files,
                    method=method,
                    params=self.session.params,
                    auth=self.auth,
                    cookies=self.cookies,
                    redirect=True,
                    data=data,
                    config=self.config,
                    timeout=self.timeout,
                    _poolmanager=self._poolmanager,
                    proxies=self.proxies,
                    verify=self.verify,
                    session=self.session,
                    cert=self.cert
                )

                request.send()
                r = request.response
                self.cookies.update(r.cookies)

            r.history = history

        self.response = r
        self.response.request = self
        self.response.cookies.update(self.cookies)

    @staticmethod
    def _encode_params(data):
        """Encode parameters in a piece of data.

        If the data supplied is a dictionary, encodes each parameter in it, and
        returns a list of tuples containing the encoded parameters, and a urlencoded
        version of that.

        Otherwise, assumes the data is already encoded appropriately, and
        returns it twice.
        """

        if isinstance(data, bytes):
            return data, data

        if hasattr(data, '__iter__') and not isinstance(data, str):
            data = dict(data)

        if hasattr(data, 'items'):
            result = []
            for k, vs in list(data.items()):
                for v in isinstance(vs, list) and vs or [vs]:
                    result.append((k.encode('utf-8') if isinstance(k, str) else k,
                                   v.encode('utf-8') if isinstance(v, str) else v))
            return result, urlencode(result, doseq=True)
        else:
            return data, data

    @property
    def full_url(self):
        """Build the actual URL to use."""

        if not self.url:
            raise URLRequired()

        url = self.url

        # Support for unicode domain names and paths.
        scheme, netloc, path, params, query, fragment = urlparse(url)

        if not scheme:
            raise MissingSchema("Invalid URL %r: No schema supplied" % url)

        if not scheme in SCHEMAS:
            raise InvalidSchema("Invalid scheme %r" % scheme)

        netloc = netloc.encode('idna').decode('utf-8')

        if not path:
            path = '/'


        if is_py2:
            if isinstance(scheme, str):
                scheme = scheme.encode('utf-8')
            if isinstance(netloc, str):
                netloc = netloc.encode('utf-8')
            if isinstance(path, str):
                path = path.encode('utf-8')
            if isinstance(params, str):
                params = params.encode('utf-8')
            if isinstance(query, str):
                query = query.encode('utf-8')
            if isinstance(fragment, str):
                fragment = fragment.encode('utf-8')

        url = (urlunparse([scheme, netloc, path, params, query, fragment]))

        if self._enc_params:
            if urlparse(url).query:
                url = '%s&%s' % (url, self._enc_params)
            else:
                url = '%s?%s' % (url, self._enc_params)

        if self.config.get('encode_uri', True):
            url = requote_uri(url)

        return url

    @property
    def path_url(self):
        """Build the path URL to use."""

        url = []

        p = urlsplit(self.full_url)

        # Proxies use full URLs.
        if p.scheme in self.proxies:
            return self.full_url

        path = p.path
        if not path:
            path = '/'

        url.append(path)

        query = p.query
        if query:
            url.append('?')
            url.append(query)

        return ''.join(url)

    def register_hook(self, event, hook):
        """Properly register a hook."""

        return self.hooks[event].append(hook)

    def send(self, anyway=False, prefetch=False):
        """Sends the request. Returns True of successful, False if not.
        If there was an HTTPError during transmission,
        self.response.status_code will contain the HTTPError code.

        Once a request is successfully sent, `sent` will equal True.

        :param anyway: If True, request will be sent, even if it has
        already been sent.
        """

        # Build the URL
        url = self.full_url

        # Logging
        if self.config.get('verbose'):
            self.config.get('verbose').write('%s   %s   %s\n' % (
                datetime.now().isoformat(), self.method, url
            ))

        # Nottin' on you.
        body = None
        content_type = None

        # Multi-part file uploads.
        if self.files:
            if not isinstance(self.data, str):

                try:
                    fields = self.data.copy()
                except AttributeError:
                    fields = dict(self.data)

                for (k, v) in list(self.files.items()):
                    # support for explicit filename
                    if isinstance(v, (tuple, list)):
                        fn, fp = v
                    else:
                        fn = guess_filename(v) or k
                        fp = v
                    fields.update({k: (fn, fp.read())})

                (body, content_type) = encode_multipart_formdata(fields)
            else:
                pass
                # TODO: Conflict?
        else:
            if self.data:

                body = self._enc_data
                if isinstance(self.data, str):
                    content_type = None
                else:
                    content_type = 'application/x-www-form-urlencoded'

        # Add content-type if it wasn't explicitly provided.
        if (content_type) and (not 'content-type' in self.headers):
            self.headers['Content-Type'] = content_type

        # Use .netrc auth if none was provided.
        if not self.auth and self.config.get('trust_env'):
            self.auth = get_netrc_auth(url)

        if self.auth:
            if isinstance(self.auth, tuple) and len(self.auth) == 2:
                # special-case basic HTTP auth
                self.auth = HTTPBasicAuth(*self.auth)

            # Allow auth to make its changes.
            r = self.auth(self)

            # Update self to reflect the auth changes.
            self.__dict__.update(r.__dict__)

        _p = urlparse(url)
        proxy = self.proxies.get(_p.scheme)

        if proxy:
            conn = poolmanager.proxy_from_url(proxy)
            _proxy = urlparse(proxy)
            if '@' in _proxy.netloc:
                auth, url = _proxy.netloc.split('@', 1)
                self.proxy_auth = HTTPProxyAuth(*auth.split(':', 1))
                r = self.proxy_auth(self)
                self.__dict__.update(r.__dict__)
        else:
            # Check to see if keep_alive is allowed.
            if self.config.get('keep_alive'):
                conn = self._poolmanager.connection_from_url(url)
            else:
                conn = connectionpool.connection_from_url(url)

        if url.startswith('https') and self.verify:

            cert_loc = None

            # Allow self-specified cert location.
            if self.verify is not True:
                cert_loc = self.verify

            # Look for configuration.
            if not cert_loc and self.config.get('trust_env'):
                cert_loc = os.environ.get('REQUESTS_CA_BUNDLE')

            # Curl compatiblity.
            if not cert_loc and self.config.get('trust_env'):
                cert_loc = os.environ.get('CURL_CA_BUNDLE')

            # Use the awesome certifi list.
            if not cert_loc:
                cert_loc = __import__('certifi').where()

            conn.cert_reqs = 'CERT_REQUIRED'
            conn.ca_certs = cert_loc
        else:
            conn.cert_reqs = 'CERT_NONE'
            conn.ca_certs = None

        if self.cert and self.verify:
            if len(self.cert) == 2:
                conn.cert_file = self.cert[0]
                conn.key_file = self.cert[1]
            else:
                conn.cert_file = self.cert

        if not self.sent or anyway:

            if self.cookies:

                # Skip if 'cookie' header is explicitly set.
                if 'cookie' not in self.headers:

                    # Simple cookie with our dict.
                    c = SimpleCookie()
                    for (k, v) in list(self.cookies.items()):
                        c[k] = v

                    # Turn it into a header.
                    cookie_header = c.output(header='', sep='; ').strip()

                    # Attach Cookie header to request.
                    self.headers['Cookie'] = cookie_header

            # Pre-request hook.
            r = dispatch_hook('pre_request', self.hooks, self)
            self.__dict__.update(r.__dict__)

            try:
                # The inner try .. except re-raises certain exceptions as
                # internal exception types; the outer suppresses exceptions
                # when safe mode is set.
                try:
                    # Send the request.
                    r = conn.urlopen(
                        method=self.method,
                        url=self.path_url,
                        body=body,
                        headers=self.headers,
                        redirect=False,
                        assert_same_host=False,
                        preload_content=False,
                        decode_content=False,
                        retries=self.config.get('max_retries', 0),
                        timeout=self.timeout,
                    )
                    self.sent = True

                except MaxRetryError as e:
                    raise ConnectionError(e)

                except (_SSLError, _HTTPError) as e:
                    if self.verify and isinstance(e, _SSLError):
                        raise SSLError(e)

                    raise Timeout('Request timed out.')

            except RequestException as e:
                if self.config.get('safe_mode', False):
                    # In safe mode, catch the exception and attach it to
                    # a blank urllib3.HTTPResponse object.
                    r = HTTPResponse()
                    r.error = e
                else:
                    raise

            self._build_response(r)

            # Response manipulation hook.
            self.response = dispatch_hook('response', self.hooks, self.response)

            # Post-request hook.
            r = dispatch_hook('post_request', self.hooks, self)
            self.__dict__.update(r.__dict__)

            # If prefetch is True, mark content as consumed.
            if prefetch:
                # Save the response.
                self.response.content

            if self.config.get('danger_mode'):
                self.response.raise_for_status()

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

        #: Resulting :class:`HTTPError` of request, if one occurred.
        self.error = None

        #: Encoding to decode with when accessing r.content.
        self.encoding = None

        #: A list of :class:`Response <Response>` objects from
        #: the history of the Request. Any redirect responses will end
        #: up here.
        self.history = []

        #: The :class:`Request <Request>` that created the Response.
        self.request = None

        #: A dictionary of Cookies the server sent back.
        self.cookies = {}

        #: Dictionary of configurations for this request.
        self.config = {}

    def __repr__(self):
        return '<Response [%s]>' % (self.status_code)

    def __bool__(self):
        """Returns true if :attr:`status_code` is 'OK'."""
        return self.ok

    def __nonzero__(self):
        """Returns true if :attr:`status_code` is 'OK'."""
        return self.ok

    @property
    def ok(self):
        try:
            self.raise_for_status()
        except RequestException:
            return False
        return True

    def iter_content(self, chunk_size=10 * 1024, decode_unicode=False):
        """Iterates over the response data.  This avoids reading the content
        at once into memory for large responses.  The chunk size is the number
        of bytes it should read into memory.  This is not necessarily the
        length of each item returned as decoding can take place.
        """
        if self._content_consumed:
            raise RuntimeError(
                'The content for this response was already consumed'
            )

        def generate():
            while 1:
                chunk = self.raw.read(chunk_size)
                if not chunk:
                    break
                yield chunk
            self._content_consumed = True

        gen = stream_untransfer(generate(), self)

        if decode_unicode:
            gen = stream_decode_response_unicode(gen, self)

        return gen

    def iter_lines(self, chunk_size=10 * 1024, decode_unicode=None):
        """Iterates over the response data, one line at a time.  This
        avoids reading the content at once into memory for large
        responses.
        """

        pending = None

        for chunk in self.iter_content(
            chunk_size=chunk_size,
            decode_unicode=decode_unicode):

            if pending is not None:
                chunk = pending + chunk
            lines = chunk.splitlines()

            if lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None

            for line in lines:
                yield line

        if pending is not None:
            yield pending

    @property
    def content(self):
        """Content of the response, in bytes."""

        if self._content is None:
            # Read the contents.
            try:
                if self._content_consumed:
                    raise RuntimeError(
                        'The content for this response was already consumed')

                if self.status_code is 0:
                    self._content = None
                else:
                    self._content = bytes().join(self.iter_content()) or bytes()

            except AttributeError:
                self._content = None

        self._content_consumed = True
        return self._content

    def _detected_encoding(self):
        try:
            detected = chardet.detect(self.content) or {}
            return detected.get('encoding')

        # Trust that chardet isn't available or something went terribly wrong.
        except Exception:
            pass


    @property
    def text(self):
        """Content of the response, in unicode.

        if Response.encoding is None and chardet module is available, encoding
        will be guessed.
        """

        # Try charset from content-type
        content = None
        encoding = self.encoding

        # Fallback to auto-detected encoding if chardet is available.
        if self.encoding is None:
            encoding = self._detected_encoding()

        # Decode unicode from given encoding.
        try:
            content = str(self.content, encoding, errors='replace')
        except LookupError:
            # A LookupError is raised if the encoding was not found which could
            # indicate a misspelling or similar mistake.
            #
            # So we try blindly encoding.
            content = str(self.content, errors='replace')
        except (UnicodeError, TypeError):
            pass

        return content

    def raise_for_status(self, allow_redirects=True):
        """Raises stored :class:`HTTPError` or :class:`URLError`, if one occurred."""

        if self.error:
            raise self.error

        if (self.status_code >= 300) and (self.status_code < 400) and not allow_redirects:
            http_error = HTTPError('%s Redirection' % self.status_code)
            http_error.response = self
            raise http_error

        elif (self.status_code >= 400) and (self.status_code < 500):
            http_error = HTTPError('%s Client Error' % self.status_code)
            http_error.response = self
            raise http_error


        elif (self.status_code >= 500) and (self.status_code < 600):
            http_error = HTTPError('%s Server Error' % self.status_code)
            http_error.response = self
            raise http_error
