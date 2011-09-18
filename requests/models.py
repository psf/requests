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


from .packages import urllib3
# print dir(urllib3)

from .config import settings
from .structures import CaseInsensitiveDict
from .utils import dict_from_cookiejar, get_unicode_from_response, stream_decode_response_unicode, decode_gzip, stream_decode_gzip
from .status_codes import codes
from .exceptions import RequestException, Timeout, URLRequired, TooManyRedirects


REDIRECT_STATI = (codes.moved, codes.found, codes.other, codes.temporary_moved)



class Request(object):
    """The :class:`Request <Request>` object. It carries out all functionality of
    Requests. Recommended interface is with the Requests functions.
    """

    def __init__(self,
        url=None, headers=dict(), files=None, method=None, data=dict(),
        params=dict(), auth=None, cookiejar=None, timeout=None, redirect=False,
        allow_redirects=False, proxies=None):

        #: Float describ the timeout of the request.
        #  (Use socket.setdefaulttimeout() as fallback)
        self.timeout = timeout

        #: Request URL.
        self.url = url

        #: Dictonary of HTTP Headers to attach to the :class:`Request <Request>`.
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

        if isinstance(auth, (list, tuple)):
            auth = AuthObject(*auth)
        if not auth:
            auth = auth_manager.get_auth(self.url)

        #: :class:`AuthObject` to attach to :class:`Request <Request>`.
        self.auth = auth

        #: CookieJar to attach to :class:`Request <Request>`.
        self.cookiejar = cookiejar

        #: True if Request has been sent.
        self.sent = False


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
            if not isinstance(self.auth.handler,
                (urllib2.AbstractBasicAuthHandler,
                urllib2.AbstractDigestAuthHandler)):

                # TODO: REMOVE THIS COMPLETELY
                auth_manager.add_password(
                    self.auth.realm, self.url,
                    self.auth.username,
                    self.auth.password)

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
        """Build internal :class:`Response <Response>` object
        from given response.
        """


        def build(resp):

            response = Response()
            response.status_code = getattr(resp, 'status', None)

            try:
                response.headers = CaseInsensitiveDict(getattr(resp, 'headers', None))
                response.raw = resp._raw

                # if self.cookiejar:

                    # response.cookies = dict_from_cookiejar(self.cookiejar)

            except AttributeError:
                pass

            if is_error:
                response.error = resp

            return response


        # Request collector.
        history = []

        # Create the lone response object.
        r = build(resp)

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
                r.raw.close()

                # Woah, this is getting crazy.
                if len(history) >= settings.max_redirects:
                    raise TooManyRedirects()

                # Add the old request to the history collector.
                history.append(r)

                # Redirect to...
                url = r.headers['location']

                # Handle redirection without scheme (see: RFC 1808 Section 4)
                if url.startswith('//'):
                    parsed_rurl = urlparse(r.url)
                    url = '%s:%s' % (parsed_rurl.scheme, url)

                # Facilitate non-RFC2616-compliant 'location' headers
                # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
                parsed_url = urlparse(url)
                if not parsed_url.netloc:
                    parsed_url = list(parsed_url)
                    parsed_url[2] = urllib.quote(parsed_url[2], safe="%/:=&?~#+!$,;'@()*[]")
                    url = urljoin(r.url, str(urlunparse(parsed_url)))

                # If 303, convert to idempotent GET.
                # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.4
                if r.status_code is codes.see_other:
                    method = 'GET'
                else:
                    method = self.method

                # Create the new Request.
                request = Request(
                    url, self.headers, self.files, method,
                    self.data, self.params, self.auth, self.cookiejar,

                    # Flag as part of a redirect loop.
                    redirect=True
                )

                # Send her away!
                request.send()
                r = request.response

            # Insert collected history.
            r.history = history

        # Attach Response to Request.
        self.response = r

        # Give Response some context.
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
        (scheme, netloc, path, params, query, fragment) = urlparse(self.url)

        # International Domain Name
        netloc = netloc.encode('idna')

        # Encode the path to to utf-8.
        if isinstance(path, unicode):
            path = path.encode('utf-8')

        # URL-encode the path.
        path = urllib.quote(path, safe="%/:=&?~#+!$,;'@()*[]")

        # Turn it back into a bytestring.
        self.url = str(urlunparse([scheme, netloc, path, params, query, fragment]))

        # Query Parameters?
        if self._enc_params:

            # If query parameters already exist in the URL, append.
            if urlparse(self.url).query:
                return '%s&%s' % (self.url, self._enc_params)

            # Otherwise, have at it.
            else:
                return '%s?%s' % (self.url, self._enc_params)

        else:
            # Kosher URL.
            return self.url


    def send(self, connection=None, anyway=False):
        """Sends the shit."""

        # Safety check.
        self._checks()

        # Build the final URL.
        url = self._build_url()

        # Setup Files.
        if self.files:
            pass

        # Setup form data.
        elif self.data:
            pass

        # Setup cookies.
        # elif self.cookies:
            # pass

        # req = _Request(url, data=self._enc_data, method=self.method)

        # Only send the Request if new or forced.
        if (anyway) or (not self.sent):

            try:
                # Create a new HTTP connection, since one wasn't passed in.
                if not connection:
                    connection = urllib3.connection_from_url(url,
                        timeout=self.timeout)

                    # One-off request. Delay fetching the content until needed.
                    do_block = False
                else:
                    # Part of a connection pool, so no fancy stuff. Sorry!
                    do_block = True

                # Create the connection.
                r = connection.urlopen(
                    method=self.method,
                    url=url,
                    body=self.data,
                    headers=self.headers,
                    redirect=False,
                    assert_same_host=False,
                    block=do_block
                )

                # Extract cookies.
                # if self.cookiejar is not None:
                    # self.cookiejar.extract_cookies(resp, req)

            # except (urllib2.HTTPError, urllib2.URLError), why:
            except Exception, why:
                # if hasattr(why, 'reason'):
                #     if isinstance(why.reason, socket.timeout):
                #         why = Timeout(why)

                # self._build_response(why, is_error=True)
                print 'FUCK'
                print why

            else:
                self._build_response(r)
                self.response.ok = True


        self.sent = self.response.ok

        return self.sent



    def old_send(self, anyway=False):
        """Sends the request. Returns True of successful, false if not.
        If there was an HTTPError during transmission,
        self.response.status_code will contain the HTTPError code.

        Once a request is successfully sent, `sent` will equal True.

        :param anyway: If True, request will be sent, even if it has
        already been sent.
        """

        self._checks()

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
        # print self.raw.__dict__
        self._content = self.raw.read() or self._response.data
        # print self.raw.__dict__

        # Decode GZip'd content.
        if 'gzip' in self.headers.get('content-encoding', ''):
            try:
                self._content = decode_gzip(self._content)
            except zlib.error:
                pass

        # Decode unicode content.
        if settings.decode_unicode:
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
        # 'basic': HTTPBasicAuthHandler,
        # 'forced_basic': HTTPForcedBasicAuthHandler,
        # 'digest': HTTPDigestAuthHandler,
        # 'proxy_basic': urllib2.ProxyBasicAuthHandler,
        # 'proxy_digest': urllib2.ProxyDigestAuthHandler
    }

    def __init__(self, username, password, handler='forced_basic', realm=None):
        self.username = username
        self.password = password
        self.realm = realm

        if isinstance(handler, basestring):
            self.handler = self._handlers.get(handler.lower(), HTTPForcedBasicAuthHandler)
        else:
            self.handler = handler
