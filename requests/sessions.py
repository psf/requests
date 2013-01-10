# -*- coding: utf-8 -*-

"""
requests.session
~~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
requests (cookies, auth, proxies).

"""
import os

from .compat import cookielib
from .cookies import cookiejar_from_dict
from .models import Request
from .hooks import dispatch_hook, default_hooks
from .utils import from_key_val_list, default_headers
from .exceptions import TooManyRedirects, InvalidSchema

from .compat import urlparse, urljoin
from .adapters import HTTPAdapter

from .utils import requote_uri, get_environ_proxies, get_netrc_auth

from .status_codes import codes
REDIRECT_STATI = (codes.moved, codes.found, codes.other, codes.temporary_moved)
DEFAULT_REDIRECT_LIMIT = 30


def merge_kwargs(local_kwarg, default_kwarg):
    """Merges kwarg dictionaries.

    If a local key in the dictionary is set to None, it will be removed.
    """

    if default_kwarg is None:
        return local_kwarg

    if isinstance(local_kwarg, str):
        return local_kwarg

    if local_kwarg is None:
        return default_kwarg

    # Bypass if not a dictionary (e.g. timeout)
    if not hasattr(default_kwarg, 'items'):
        return local_kwarg

    default_kwarg = from_key_val_list(default_kwarg)
    local_kwarg = from_key_val_list(local_kwarg)

    # Update new values in a case-insensitive way
    def get_original_key(original_keys, new_key):
        """
        Finds the key from original_keys that case-insensitive matches new_key.
        """
        for original_key in original_keys:
            if key.lower() == original_key.lower():
                return original_key
        return new_key

    kwargs = default_kwarg.copy()
    original_keys = kwargs.keys()
    for key, value in local_kwarg.items():
        kwargs[get_original_key(original_keys, key)] = value

    # Remove keys that are set to None.
    for (k, v) in local_kwarg.items():
        if v is None:
            del kwargs[k]

    return kwargs


class SessionRedirectMixin(object):

    def resolve_redirects(self, resp, req, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Receives a Response. Returns a generator of Responses."""

        i = 0

        # ((resp.status_code is codes.see_other))
        while (('location' in resp.headers and resp.status_code in REDIRECT_STATI)):

            resp.content  # Consume socket so it can be released

            if i >= self.max_redirects:
                raise TooManyRedirects('Exceeded %s redirects.' % self.max_redirects)

            # Release the connection back into the pool.
            resp.close()

            url = resp.headers['location']
            method = req.method

            # Handle redirection without scheme (see: RFC 1808 Section 4)
            if url.startswith('//'):
                parsed_rurl = urlparse(resp.url)
                url = '%s:%s' % (parsed_rurl.scheme, url)

            # Facilitate non-RFC2616-compliant 'location' headers
            # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
            if not urlparse(url).netloc:
                # Compliant with RFC3986, we percent encode the url.
                url = urljoin(resp.url, requote_uri(url))

            # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.4
            if resp.status_code is codes.see_other and req.method != 'HEAD':
                method = 'GET'

            # Do what the browsers do, despite standards...
            if resp.status_code in (codes.moved, codes.found) and req.method == 'POST':
                method = 'GET'

            # Remove the cookie headers that were sent.
            headers = req.headers
            try:
                del headers['Cookie']
            except KeyError:
                pass

            resp = self.request(
                    url=url,
                    method=method,
                    headers=headers,
                    auth=req.auth,
                    cookies=req.cookies,
                    allow_redirects=False,
                    stream=stream,
                    timeout=timeout,
                    verify=verify,
                    cert=cert,
                    proxies=proxies
                )

            i += 1
            yield resp


class Session(SessionRedirectMixin):
    """A Requests session.

    Provides cookie persistience, connection-pooling, and configuration.

    Basic Usage::

      >>> import requests
      >>> s = requests.Session()
      >>> s.get('http://httpbin.org/get')
      200
    """

    def __init__(self):

        #: A case-insensitive dictionary of headers to be sent on each
        #: :class:`Request <Request>` sent from this
        #: :class:`Session <Session>`.
        self.headers = default_headers()

        #: Default Authentication tuple or object to attach to
        #: :class:`Request <Request>`.
        self.auth = None

        #: Dictionary mapping protocol to the URL of the proxy (e.g.
        #: {'http': 'foo.bar:3128'}) to be used on each
        #: :class:`Request <Request>`.
        self.proxies = {}

        #: Event-handling hooks.
        self.hooks = default_hooks()

        #: Dictionary of querystring data to attach to each
        #: :class:`Request <Request>`. The dictionary values may be lists for
        #: representing multivalued query parameters.
        self.params = {}

        #: Stream response content default.
        self.stream = False

        #: SSL Verification default.
        self.verify = True

        #: SSL certificate default.
        self.cert = None

        #: Maximum number of redirects to follow.
        self.max_redirects = DEFAULT_REDIRECT_LIMIT

        #: Should we trust the environment?
        self.trust_env = True

        # Set up a CookieJar to be used by default
        self.cookies = cookiejar_from_dict({})

        # Default connection adapters.
        self.adapters = {}
        self.mount('http://', HTTPAdapter())
        self.mount('https://', HTTPAdapter())

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def request(self, method, url,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        timeout=None,
        allow_redirects=True,
        proxies=None,
        hooks=None,
        stream=None,
        verify=None,
        cert=None):

        cookies = cookies or {}
        proxies = proxies or {}

        # Bootstrap CookieJar.
        if not isinstance(cookies, cookielib.CookieJar):
            cookies = cookiejar_from_dict(cookies)

        # Bubble down session cookies.
        for cookie in self.cookies:
            cookies.set_cookie(cookie)

        # Gather clues from the surrounding environment.
        if self.trust_env:
            # Set environment's proxies.
            env_proxies = get_environ_proxies(url) or {}
            for (k, v) in env_proxies.items():
                proxies.setdefault(k, v)

            # Set environment's basic authentication.
            if not auth:
                auth = get_netrc_auth(url)

            # Look for configuration.
            if not verify and verify is not False:
                verify = os.environ.get('REQUESTS_CA_BUNDLE')

            # Curl compatibility.
            if not verify and verify is not False:
                verify = os.environ.get('CURL_CA_BUNDLE')


        # Merge all the kwargs.
        params = merge_kwargs(params, self.params)
        headers = merge_kwargs(headers, self.headers)
        auth = merge_kwargs(auth, self.auth)
        proxies = merge_kwargs(proxies, self.proxies)
        hooks = merge_kwargs(hooks, self.hooks)
        stream = merge_kwargs(stream, self.stream)
        verify = merge_kwargs(verify, self.verify)
        cert = merge_kwargs(cert, self.cert)


        # Create the Request.
        req = Request()
        req.method = method.upper()
        req.url = url
        req.headers = headers
        req.files = files
        req.data = data
        req.params = params
        req.auth = auth
        req.cookies = cookies
        req.hooks = hooks

        # Prepare the Request.
        prep = req.prepare()

        # Send the request.
        resp = self.send(prep, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)

        # Persist cookies.
        for cookie in resp.cookies:
            self.cookies.set_cookie(cookie)

        # Redirect resolving generator.
        gen = self.resolve_redirects(resp, req, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)

        # Resolve redirects if allowed.
        history = [r for r in gen] if allow_redirects else []

        # Shuffle things around if there's history.
        if history:
            history.insert(0, resp)
            resp = history.pop()
            resp.history = tuple(history)

        # Response manipulation hook.
        self.response = dispatch_hook('response', hooks, resp)

        return resp

    def get(self, url, **kwargs):
        """Sends a GET request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        kwargs.setdefault('allow_redirects', True)
        return self.request('GET', url, **kwargs)

    def options(self, url, **kwargs):
        """Sends a OPTIONS request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        kwargs.setdefault('allow_redirects', True)
        return self.request('OPTIONS', url, **kwargs)

    def head(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        kwargs.setdefault('allow_redirects', False)
        return self.request('HEAD', url, **kwargs)

    def post(self, url, data=None, **kwargs):
        """Sends a POST request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('POST', url, data=data, **kwargs)

    def put(self, url, data=None, **kwargs):
        """Sends a PUT request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('PUT', url, data=data, **kwargs)

    def patch(self, url, data=None, **kwargs):
        """Sends a PATCH request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('PATCH', url,  data=data, **kwargs)

    def delete(self, url, **kwargs):
        """Sends a DELETE request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('DELETE', url, **kwargs)

    def send(self, request, **kwargs):
        """Send a given PreparedRequest."""
        adapter = self.get_adapter(url=request.url)
        r = adapter.send(request, **kwargs)
        return r

    def get_adapter(self, url):
        """Returns the appropriate connnection adapter for the given URL."""
        for (prefix, adapter) in self.adapters.items():

            if url.startswith(prefix):
                return adapter

        # Nothing matches :-/
        raise InvalidSchema("No connection adapters were found for '%s'" % url)

    def close(self):
        """Closes all adapters and as such the session"""
        for _, v in self.adapters.items():
            v.close()

    def mount(self, prefix, adapter):
        """Registers a connection adapter to a prefix."""
        self.adapters[prefix] = adapter

    def __getstate__(self):
        return dict((attr, getattr(self, attr, None)) for attr in self.__attrs__)

    def __setstate__(self, state):
        for attr, value in state.items():
            setattr(self, attr, value)


def session():
    """Returns a :class:`Session` for context-management."""

    return Session()
