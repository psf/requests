from typing import Any, Callable
import hashlib

def get_hash_function(algorithm: str) -> Callable[[Any], str]:

    def md5_utf8(x: str | bytes) -> str:
        if isinstance(x, str):
            x = x.encode('utf-8')
        return hashlib.md5(x, usedforsecurity=False).hexdigest()

    def sha_utf8(x: str | bytes) -> str:
        if isinstance(x, str):
            x = x.encode('utf-8')
        return hashlib.sha1(x, usedforsecurity=False).hexdigest()

    def sha256_utf8(x: str | bytes) -> str:
        if isinstance(x, str):
            x = x.encode('utf-8')
        return hashlib.sha256(x, usedforsecurity=False).hexdigest()

    def sha512_utf8(x: str | bytes) -> str:
        if isinstance(x, str):
            x = x.encode('utf-8')
        return hashlib.sha512(x, usedforsecurity=False).hexdigest()
    algorithms = {'MD5': md5_utf8, 'MD5-SESS': md5_utf8, 'SHA': sha_utf8, 'SHA-256': sha256_utf8, 'SHA-512': sha512_utf8}
    return algorithms.get(algorithm, lambda x: '')
from typing import Any

def rewind_request_body(r: Any, pos: Any) -> None:
    if pos is None:
        return
    seek = getattr(r.request.body, 'seek', None)
    if seek is not None:
        seek(pos)
'\nrequests.auth\n~~~~~~~~~~~~~\n\nThis module contains the authentication handlers for Requests.\n'
from __future__ import annotations
import hashlib
import os
import re
import threading
import time
import warnings
from base64 import b64encode
from typing import TYPE_CHECKING, Any, Final, cast, overload
from ._internal_utils import to_native_string
from .compat import basestring, str, urlparse
from .cookies import extract_cookies_to_jar
from .utils import parse_dict_header
if TYPE_CHECKING:
    from http.cookiejar import CookieJar
    from typing import Any
    from .models import PreparedRequest, Response
CONTENT_TYPE_FORM_URLENCODED: Final = 'application/x-www-form-urlencoded'
CONTENT_TYPE_MULTI_PART: Final = 'multipart/form-data'

def _basic_auth_str(username: bytes | str, password: bytes | str) -> str:
    """Returns a Basic Auth string."""
    if not isinstance(username, basestring):
        warnings.warn(f"Non-string usernames will no longer be supported in Requests 3.0.0. Please convert the object you've passed in ({username!r}) to a string or bytes object in the near future to avoid problems.", category=DeprecationWarning)
        username = str(username)
    if not isinstance(password, basestring):
        warnings.warn(f"Non-string passwords will no longer be supported in Requests 3.0.0. Please convert the object you've passed in ({type(password)!r}) to a string or bytes object in the near future to avoid problems.", category=DeprecationWarning)
        password = str(password)
    if isinstance(username, str):
        username = username.encode('latin1')
    if isinstance(password, str):
        password = password.encode('latin1')
    authstr = 'Basic ' + to_native_string(b64encode(b':'.join((username, password))).strip())
    return authstr

class AuthBase:
    """Base class that all auth implementations derive from"""

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        raise NotImplementedError('Auth hooks must be callable.')

class HTTPBasicAuth(AuthBase):
    """Attaches HTTP Basic Authentication to the given Request object."""
    username: bytes | str
    password: bytes | str

    @overload
    def __init__(self, username: str, password: str) -> None:
        ...

    @overload
    def __init__(self, username: bytes, password: bytes) -> None:
        ...

    def __init__(self, username: bytes | str, password: bytes | str) -> None:
        self.username = username
        self.password = password

    def __eq__(self, other: object) -> bool:
        return all([self.username == getattr(other, 'username', None), self.password == getattr(other, 'password', None)])

    def __ne__(self, other: Any) -> bool:
        return not self == other

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        r.headers['Authorization'] = _basic_auth_str(self.username, self.password)
        return r

class HTTPProxyAuth(HTTPBasicAuth):
    """Attaches HTTP Proxy Authentication to a given Request object."""

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        r.headers['Proxy-Authorization'] = _basic_auth_str(self.username, self.password)
        return r

class HTTPDigestAuth(AuthBase):
    """Attaches HTTP Digest Authentication to the given Request object."""
    username: bytes | str
    password: bytes | str
    _thread_local: threading.local
    last_nonce: str
    nonce_count: int
    chal: dict[str, str]
    pos: int | None
    num_401_calls: int | None

    @overload
    def __init__(self, username: str, password: str) -> None:
        ...

    @overload
    def __init__(self, username: bytes, password: bytes) -> None:
        ...

    def __init__(self, username: bytes | str, password: bytes | str) -> None:
        self.username = username
        self.password = password
        self._thread_local = threading.local()

    def init_per_thread_state(self) -> None:
        if not hasattr(self._thread_local, 'init'):
            self._thread_local.init = True
            self._thread_local.last_nonce = ''
            self._thread_local.nonce_count = 0
            self._thread_local.chal = {}
            self._thread_local.pos = None
            self._thread_local.num_401_calls = None

    def build_digest_header(self, method: str, url: str) -> str | None:
        """
        :rtype: str
        """
        realm = self._thread_local.chal['realm']
        nonce = self._thread_local.chal['nonce']
        qop = self._thread_local.chal.get('qop')
        algorithm = self._thread_local.chal.get('algorithm')
        opaque = self._thread_local.chal.get('opaque')
        hash_utf8 = None
        if algorithm is None:
            _algorithm = 'MD5'
        else:
            _algorithm = algorithm.upper()
        hash_utf8 = get_hash_function(algorithm)
        if hash_utf8 is None:
            return None

        def KD(s: str, d: str) -> str:
            return hash_utf8(f'{s}:{d}')
        entdig = None
        p_parsed = urlparse(url)
        path = p_parsed.path or '/'
        if p_parsed.query:
            path += f'?{p_parsed.query}'
        A1 = f'{self.username}:{realm}:{self.password}'
        A2 = f'{method}:{path}'
        HA1 = hash_utf8(A1)
        HA2 = hash_utf8(A2)
        if nonce == self._thread_local.last_nonce:
            self._thread_local.nonce_count += 1
        else:
            self._thread_local.nonce_count = 1
        ncvalue = f'{self._thread_local.nonce_count:08x}'
        s = str(self._thread_local.nonce_count).encode('utf-8')
        s += nonce.encode('utf-8')
        s += time.ctime().encode('utf-8')
        s += os.urandom(8)
        cnonce = hashlib.sha1(s, usedforsecurity=False).hexdigest()[:16]
        if _algorithm == 'MD5-SESS':
            HA1 = hash_utf8(f'{HA1}:{nonce}:{cnonce}')
        if not qop:
            respdig = KD(HA1, f'{nonce}:{HA2}')
        elif qop == 'auth' or 'auth' in qop.split(','):
            noncebit = f'{nonce}:{ncvalue}:{cnonce}:auth:{HA2}'
            respdig = KD(HA1, noncebit)
        else:
            return None
        self._thread_local.last_nonce = nonce
        base = f'username="{self.username}", realm="{realm}", nonce="{nonce}", uri="{path}", response="{respdig}"'
        if opaque:
            base += f', opaque="{opaque}"'
        if algorithm:
            base += f', algorithm="{algorithm}"'
        if entdig:
            base += f', digest="{entdig}"'
        if qop:
            base += f', qop="auth", nc={ncvalue}, cnonce="{cnonce}"'
        return f'Digest {base}'

    def handle_redirect(self, r: Response, **kwargs: Any) -> None:
        """Reset num_401_calls counter on redirects."""
        if r.is_redirect:
            self._thread_local.num_401_calls = 1

    def handle_401(self, r: Response, **kwargs: Any) -> Response:
        """
        Takes the given response and tries digest-auth, if needed.

        :rtype: requests.Response
        """
        if not 400 <= r.status_code < 500:
            self._thread_local.num_401_calls = 1
            return r
        rewind_request_body(r, pos)
        s_auth = r.headers.get('www-authenticate', '')
        if 'digest' in s_auth.lower() and self._thread_local.num_401_calls < 2:
            self._thread_local.num_401_calls += 1
            pat = re.compile('digest ', flags=re.IGNORECASE)
            self._thread_local.chal = parse_dict_header(pat.sub('', s_auth, count=1))
            r.content
            r.close()
            prep = r.request.copy()
            cookie_jar = cast('CookieJar', prep._cookies)
            extract_cookies_to_jar(cookie_jar, r.request, r.raw)
            prep.prepare_cookies(cookie_jar)
            _digest_auth = self.build_digest_header(cast(str, prep.method), cast(str, prep.url))
            if _digest_auth:
                prep.headers['Authorization'] = _digest_auth
            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep
            return _r
        self._thread_local.num_401_calls = 1
        return r

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        self.init_per_thread_state()
        if self._thread_local.last_nonce:
            _digest_auth = self.build_digest_header(cast(str, r.method), cast(str, r.url))
            if _digest_auth:
                r.headers['Authorization'] = _digest_auth
        if (tell := getattr(r.body, 'tell', None)) is not None:
            self._thread_local.pos = tell()
        else:
            self._thread_local.pos = None
        r.register_hook('response', self.handle_401)
        r.register_hook('response', self.handle_redirect)
        self._thread_local.num_401_calls = 1
        return r

    def __eq__(self, other: object) -> bool:
        return all([self.username == getattr(other, 'username', None), self.password == getattr(other, 'password', None)])

    def __ne__(self, other: Any) -> bool:
        return not self == other