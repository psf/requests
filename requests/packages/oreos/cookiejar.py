"""
Wrapper for CookieJar allow dict-like access.
Ideally there would be wrappers for LWPCookieJar and MozillaCookieJar as well.
"""

import urlparse
import Cookie
from Cookie import Morsel
import cookielib
import collections

class MockRequest:
    """
    Wraps a *requests.Request* to mimic a *urllib2.Request*.
    """
    def __init__(self, request):
        self._r = request
    
    def get_type(self):
        return urlparse.urlparse(self._r.full_url).scheme
    
    def get_host(self):
        return urlparse.urlparse(self._r.full_url).netloc
    
    def get_origin_req_host(self):
        if self._r.response.history:
            r = self._r.response.history[0]
            return urlparse.urlparse(r).netloc
        else:
            return self.get_host()
    
    def get_full_url(self):
        return self._r.full_url
    
    def has_header(self, name):
        return name in self._r.headers
    
    def get_header(self, name, default=None):
        return self._r.headers.get(name, default)
    
    def add_unredirected_header(self, name, value):
        # XXX: This is incorrect.
        # To do this correctly the *requests.Request* class would need
        # to keep track of headers that are only sent with the original
        # request.
        self._r.headers[name] = value
    
    def is_unverifiable(self):
        # unverifiable == redirected
        return bool(self._r.response.history)

class MockResponse:
    """
    Wraps a *requests.Response* to mimic a *urllib.addinfourl*.
    """
    def __init__(self, response):
        self._r = response
    
    def info(self):
        return self._r.msg
    
    def getheaders(self, name):
        self._r.msg.getheaders(name)

class CookieJar(cookielib.CookieJar, collections.MutableMapping):
    def extract_cookies(self, response, request):
        if response.raw._original_response:
            req = MockRequest(request)
            res = MockResponse(response.raw._original_response)
            cookielib.CookieJar.extract_cookies(self, res, req)
    
    def get_header(self, request):
        r = MockRequest(request)
        self.add_cookie_header(r)
        return r._r.headers['Cookie']
    
    def get(self, name, domain=None, path=None, default=None):
        try:
            return self._find(name, domain, path)
        except KeyError:
            return default
    
    def set(self, name, value, **kwargs):
        if isinstance(value, Morsel):
            c = morsel_to_cookielib(value)
        else:
            c = create_cookie(name, value, **kwargs)
        self.set_cookie(c)
        return c
    
    def update(self, other):
        if isinstance(other, cookielib.CookieJar):
            for cookie in other:
                self.set_cookie(cookie)
        else:
            collections.MutableMapping.update(self, other)
    
    def __getitem__(self, name):
        return self._find(name)
    
    def __setitem__(self, name, value):
        self.set(name, value)
    
    def __delitem__(self, name):
        raise NotImplementedError('cookies can be removed using *clear*')
    
    def _find(self, name, domain=None, path=None):
        try:
            if domain is None:
                dompaths = self._cookies.itervalues()
            else:
                dompaths = [self._cookies[domain]]
            for paths in dompaths:
                if path is None:
                    pathcookies = paths.itervalues()
                else:
                    pathcookies = [paths[path]]
                for cookies in pathcookies:
                    for cname, cookie in cookies.iteritems():
                        if name == cname:
                            return cookielib_to_morsel(cookie)
        except KeyError:
            pass
        raise KeyError('name=%r, domain=%r, path=%r' % (name, domain, path))

def create_cookie(name, value, **kwargs):
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

def cookielib_to_morsel(cookie):
    m = Morsel()
    m.key = cookie.name
    m.value = cookie.value
    m.coded_value = Cookie._quote(cookie.value)
    m.update({
        'expires': cookie.expires or '',
        'path': cookie.path or '',
        'comment': cookie.comment or '',
        'domain': cookie.domain or '',
        'max-age': cookie.expires or '',
        'secure': cookie.secure or '',
        'httponly': cookie._rest.get('HttpOnly', ''),
        'version': cookie.version or '',
        })
    return m

def morsel_to_cookielib(morsel):
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
