"""
Compatibility code to be able to use `cookielib.CookieJar` with requests.

requests.utils imports from here, so be careful with imports.
"""

import collections
from .compat import cookielib, urlparse, Morsel

try:
    import threading
    # grr, pyflakes: this fixes "redefinition of unused 'threading'"
    threading
except ImportError:
    import dummy_threading as threading

class MockRequest(object):
    """Wraps a `requests.Request` to mimic a `urllib2.Request`.

    The code in `cookielib.CookieJar` expects this interface in order to correctly
    manage cookie policies, i.e., determine whether a cookie can be set, given the
    domains of the request and the cookie.

    The original request object is read-only. The client is responsible for collecting
    the new headers via `get_new_headers()` and interpreting them appropriately. You
    probably want `get_cookie_header`, defined below.
    """

    def __init__(self, request):
        self._r = request
        self._new_headers = {}

    def get_type(self):
        return urlparse(self._r.full_url).scheme

    def get_host(self):
        return urlparse(self._r.full_url).netloc

    def get_origin_req_host(self):
        if self._r.response.history:
            r = self._r.response.history[0]
            return urlparse(r).netloc
        else:
            return self.get_host()

    def get_full_url(self):
        return self._r.full_url

    def is_unverifiable(self):
        # unverifiable == redirected
        return bool(self._r.response.history)

    def has_header(self, name):
        return name in self._r.headers or name in self._new_headers

    def get_header(self, name, default=None):
        return self._r.headers.get(name, self._new_headers.get(name, default))

    def add_header(self, key, val):
        """cookielib has no legitimate use for this method; add it back if you find one."""
        raise NotImplementedError("Cookie headers should be added with add_unredirected_header()")

    def add_unredirected_header(self, name, value):
        self._new_headers[name] = value

    def get_new_headers(self):
        return self._new_headers

class MockResponse(object):
    """Wraps a `httplib.HTTPMessage` to mimic a `urllib.addinfourl`.

    ...what? Basically, expose the parsed HTTP headers from the server response
    the way `cookielib` expects to see them.
    """

    def __init__(self, headers):
        """Make a MockResponse for `cookielib` to read.

        :param headers: a httplib.HTTPMessage or analogous carrying the headers
        """
        self._headers = headers

    def info(self):
        return self._headers

    def getheaders(self, name):
        self._headers.getheaders(name)

def extract_cookies_to_jar(jar, request, response):
    """Extract the cookies from the response into a CookieJar.

    :param jar: cookielib.CookieJar (not necessarily a RequestsCookieJar)
    :param request: our own requests.Request object
    :param response: urllib3.HTTPResponse object
    """
    # the _original_response field is the wrapped httplib.HTTPResponse object,
    # and in safe mode, it may be None if the request didn't actually complete.
    # in that case, just skip the cookie extraction.
    if response._original_response is not None:
        req = MockRequest(request)
        # pull out the HTTPMessage with the headers and put it in the mock:
        res = MockResponse(response._original_response.msg)
        jar.extract_cookies(res, req)

def get_cookie_header(jar, request):
    """Produce an appropriate Cookie header string to be sent with `request`, or None."""
    r = MockRequest(request)
    jar.add_cookie_header(r)
    return r.get_new_headers().get('Cookie')

def remove_cookie_by_name(cookiejar, name, domain=None, path=None):
    """Unsets a cookie by name, by default over all domains and paths.

    Wraps CookieJar.clear(), is O(n).
    """
    clearables = []
    for cookie in cookiejar:
        if cookie.name == name:
            if domain is None or domain == cookie.domain:
                if path is None or path == cookie.path:
                    clearables.append((cookie.domain, cookie.path, cookie.name))

    for domain, path, name in clearables:
        cookiejar.clear(domain, path, name)

class RequestsCookieJar(cookielib.CookieJar, collections.MutableMapping):
    """Compatibility class; is a cookielib.CookieJar, but exposes a dict interface.

    This is the CookieJar we create by default for requests and sessions that
    don't specify one, since some clients may expect response.cookies and
    session.cookies to support dict operations.

    Don't use the dict interface internally; it's just for compatibility with
    with external client code. All `requests` code should work out of the box
    with externally provided instances of CookieJar, e.g., LWPCookieJar and
    FileCookieJar.

    Caution: dictionary operations that are normally O(1) may be O(n).

    Unlike a regular CookieJar, this class is pickleable.
    """

    def get(self, name, domain=None, path=None, default=None):
        try:
            return self._find(name, domain, path)
        except KeyError:
            return default

    def set(self, name, value, **kwargs):
        # support client code that unsets cookies by assignment of a None value:
        if value is None:
            remove_cookie_by_name(self, name, domain=kwargs.get('domain'), path=kwargs.get('path'))
            return

        if isinstance(value, Morsel):
            c = morsel_to_cookie(value)
        else:
            c = create_cookie(name, value, **kwargs)
        self.set_cookie(c)
        return c

    def __getitem__(self, name):
        return self._find(name)

    def __setitem__(self, name, value):
        self.set(name, value)

    def __delitem__(self, name):
        remove_cookie_by_name(self, name)

    def _find(self, name, domain=None, path=None):
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        return cookie.value

        raise KeyError('name=%r, domain=%r, path=%r' % (name, domain, path))

    def __getstate__(self):
        state = self.__dict__.copy()
        # remove the unpickleable RLock object
        state.pop('_cookies_lock')
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        if '_cookies_lock' not in self.__dict__:
            self._cookies_lock = threading.RLock()

    def copy(self):
        """We're probably better off forbidding this."""
        raise NotImplementedError

def create_cookie(name, value, **kwargs):
    """Make a cookie from underspecified parameters.

    By default, the pair of `name` and `value` will be set for the domain ''
    and sent on every request (this is sometimes called a "supercookie").
    """
    result = dict(
        version=0,
        name=name,
        value=value,
        port=None,
        domain='',
        path='/',
        secure=False,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={'HttpOnly': None},
        rfc2109=False,
        )

    badargs = set(kwargs) - set(result)
    if badargs:
        err = 'create_cookie() got unexpected keyword arguments: %s'
        raise TypeError(err % list(badargs))

    result.update(kwargs)
    result['port_specified'] = bool(result['port'])
    result['domain_specified'] = bool(result['domain'])
    result['domain_initial_dot'] = result['domain'].startswith('.')
    result['path_specified'] = bool(result['path'])

    return cookielib.Cookie(**result)

def morsel_to_cookie(morsel):
    """Convert a Morsel object into a Cookie containing the one k/v pair."""
    c = create_cookie(
        name=morsel.key,
        value=morsel.value,
        version=morsel['version'] or 0,
        port=None,
        port_specified=False,
        domain=morsel['domain'],
        domain_specified=bool(morsel['domain']),
        domain_initial_dot=morsel['domain'].startswith('.'),
        path=morsel['path'],
        path_specified=bool(morsel['path']),
        secure=bool(morsel['secure']),
        expires=morsel['max-age'] or morsel['expires'],
        discard=False,
        comment=morsel['comment'],
        comment_url=bool(morsel['comment']),
        rest={'HttpOnly': morsel['httponly']},
        rfc2109=False,
        )
    return c

def cookiejar_from_dict(cookie_dict, cookiejar=None):
    """Returns a CookieJar from a key/value dictionary.

    :param cookie_dict: Dict of key/values to insert into CookieJar.
    """
    if cookiejar is None:
        cookiejar = RequestsCookieJar()

    if cookie_dict is not None:
        for name in cookie_dict:
            cookiejar.set_cookie(create_cookie(name, cookie_dict[name]))
    return cookiejar
