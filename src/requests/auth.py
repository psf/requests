"""
requests.auth
~~~~~~~~~~~~~

This module contains the authentication handlers for Requests.
"""

import hashlib
import os
import re
import threading
import time
import warnings
from base64 import b64encode
from typing import Any, Callable, Optional

from ._internal_utils import to_native_string
# pylint: disable=redefined-builtin
from .compat import basestring, str, urlparse
# pylint: enable=redefined-builtin
from .cookies import extract_cookies_to_jar
from .utils import parse_dict_header

CONTENT_TYPE_FORM_URLENCODED = "application/x-www-form-urlencoded"
CONTENT_TYPE_MULTI_PART = "multipart/form-data"


def _basic_auth_str(username: Any, password: Any) -> str:
    """Returns a Basic Auth string."""

    # "I want us to put a big-ol' comment on top of it that
    # says that this behaviour is dumb but we need to preserve
    # it because people are relying on it."
    #    - Lukasa
    #
    # These are here solely to maintain backwards compatibility
    # for things like ints. This will be removed in 3.0.0.
    if not isinstance(username, basestring):
        warnings.warn(
            f"Non-string usernames will no longer be supported in Requests "
            f"3.0.0. Please convert the object you've passed in ({username!r}) to "
            f"a string or bytes object in the near future to avoid "
            f"problems.",
            category=DeprecationWarning,
        )
        username = str(username)

    if not isinstance(password, basestring):
        warnings.warn(
            f"Non-string passwords will no longer be supported in Requests "
            f"3.0.0. Please convert the object you've passed in ({type(password)!r}) to "
            f"a string or bytes object in the near future to avoid "
            f"problems.",
            category=DeprecationWarning,
        )
        password = str(password)
    # -- End Removal --

    if isinstance(username, str):
        username = username.encode("latin1")

    if isinstance(password, str):
        password = password.encode("latin1")

    authstr = "Basic " + to_native_string(
        b64encode(b":".join((username, password))).strip()
    )

    return authstr


class AuthBase:
    """Base class that all auth implementations derive from"""

    def __call__(self, req: Any) -> Any:
        """Apply authentication to the request."""
        raise NotImplementedError("Auth hooks must be callable.")


class HTTPBasicAuth(AuthBase):
    """Attaches HTTP Basic Authentication to the given Request object."""

    def __init__(self, username: Any, password: Any) -> None:
        self.username = username
        self.password = password

    def __eq__(self, other: Any) -> bool:
        return all(
            [
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
            ]
        )

    def __ne__(self, other: Any) -> bool:
        return not self == other

    def __call__(self, req: Any) -> Any:
        """Apply basic authentication to the request."""
        req.headers["Authorization"] = _basic_auth_str(self.username, self.password)
        return req


class HTTPProxyAuth(HTTPBasicAuth):
    """Attaches HTTP Proxy Authentication to a given Request object."""

    def __call__(self, req: Any) -> Any:
        """Apply proxy authentication to the request."""
        req.headers["Proxy-Authorization"] = _basic_auth_str(self.username, self.password)
        return req


class HTTPDigestAuth(AuthBase):
    """Attaches HTTP Digest Authentication to the given Request object."""

    def __init__(self, username: Any, password: Any) -> None:
        self.username = username
        self.password = password
        # Keep state in per-thread local storage
        self._thread_local = threading.local()

    def init_per_thread_state(self) -> None:
        # Ensure state is initialized just once per-thread
        if not hasattr(self._thread_local, "init"):
            self._thread_local.init = True
            self._thread_local.last_nonce = ""
            self._thread_local.nonce_count = 0
            self._thread_local.chal = {}
            self._thread_local.pos = None
            self._thread_local.num_401_calls = None

    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    def build_digest_header(self, method: Any, url: Any) -> Optional[str]:
        """Build digest authentication header.
        
        :rtype: str
        """

        realm = self._thread_local.chal["realm"]
        nonce = self._thread_local.chal["nonce"]
        qop = self._thread_local.chal.get("qop")
        algorithm = self._thread_local.chal.get("algorithm")
        opaque = self._thread_local.chal.get("opaque")
        hash_utf8: Optional[Callable[[Any], str]] = None

        if algorithm is None:
            _algorithm = "MD5"
        else:
            _algorithm = algorithm.upper()
        # lambdas assume digest modules are imported at the top level
        # pylint: disable=invalid-name
        if _algorithm in ("MD5", "MD5-SESS"):

            def md5_utf8(data: Any) -> str:
                """Hash data using MD5."""
                if isinstance(data, str):
                    data = data.encode("utf-8")
                return hashlib.md5(data).hexdigest()

            hash_utf8 = md5_utf8
        elif _algorithm == "SHA":

            def sha_utf8(data: Any) -> str:
                """Hash data using SHA-1."""
                if isinstance(data, str):
                    data = data.encode("utf-8")
                return hashlib.sha1(data).hexdigest()

            hash_utf8 = sha_utf8
        elif _algorithm == "SHA-256":

            def sha256_utf8(data: Any) -> str:
                """Hash data using SHA-256."""
                if isinstance(data, str):
                    data = data.encode("utf-8")
                return hashlib.sha256(data).hexdigest()

            hash_utf8 = sha256_utf8
        elif _algorithm == "SHA-512":

            def sha512_utf8(data: Any) -> str:
                """Hash data using SHA-512."""
                if isinstance(data, str):
                    data = data.encode("utf-8")
                return hashlib.sha512(data).hexdigest()

            hash_utf8 = sha512_utf8

        # KD is standard digest auth notation
        def digest_key_derivation(secret: str, data: str) -> str:
            """Key derivation function for digest authentication."""
            assert hash_utf8 is not None  # type narrowing for mypy
            return hash_utf8(f"{secret}:{data}")

        KD = digest_key_derivation  # noqa:E741

        if hash_utf8 is None:
            return None

        # XXX not implemented yet - entdig would be used for entity digest
        p_parsed = urlparse(url)
        #: path is request-uri defined in RFC 2616 which should not be empty
        path = p_parsed.path or "/"
        if p_parsed.query:
            path += f"?{p_parsed.query}"

        # A1, A2, HA1, HA2 are standard digest auth notation (RFC 2617)
        A1 = f"{self.username}:{realm}:{self.password}"  # noqa:N806
        A2 = f"{method}:{path}"  # noqa:N806

        HA1 = hash_utf8(A1)  # noqa:N806
        HA2 = hash_utf8(A2)  # noqa:N806

        if nonce == self._thread_local.last_nonce:
            self._thread_local.nonce_count += 1
        else:
            self._thread_local.nonce_count = 1
        ncvalue = f"{self._thread_local.nonce_count:08x}"
        cnonce_data = str(self._thread_local.nonce_count).encode("utf-8")
        cnonce_data += nonce.encode("utf-8")
        cnonce_data += time.ctime().encode("utf-8")
        cnonce_data += os.urandom(8)

        cnonce = hashlib.sha1(cnonce_data).hexdigest()[:16]
        if _algorithm == "MD5-SESS":
            HA1 = hash_utf8(f"{HA1}:{nonce}:{cnonce}")  # noqa:N806

        if not qop:
            respdig = KD(HA1, f"{nonce}:{HA2}")
        elif qop == "auth" or "auth" in qop.split(","):
            noncebit = f"{nonce}:{ncvalue}:{cnonce}:auth:{HA2}"
            respdig = KD(HA1, noncebit)
        else:
            # XXX handle auth-int.
            return None

        self._thread_local.last_nonce = nonce

        # XXX should the partial digests be encoded too?
        base = (
            f'username="{self.username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{path}", response="{respdig}"'
        )
        if opaque:
            base += f', opaque="{opaque}"'
        if algorithm:
            base += f', algorithm="{algorithm}"'
        # if entdig:  # XXX not implemented yet - entdig is always None
        #     base += f', digest="{entdig}"'
        if qop:
            base += f', qop="auth", nc={ncvalue}, cnonce="{cnonce}"'

        return f"Digest {base}"
    # pylint: enable=too-many-locals,too-many-branches,too-many-statements,invalid-name

    def handle_redirect(self, resp: Any, **kwargs: Any) -> None:  # pylint: disable=unused-argument
        """Reset num_401_calls counter on redirects."""
        if resp.is_redirect:
            self._thread_local.num_401_calls = 1

    def handle_401(self, resp: Any, **kwargs: Any) -> Any:
        """Takes the given response and tries digest-auth, if needed.
        
        :rtype: requests.Response
        """

        # If response is not 4xx, do not auth
        # See https://github.com/psf/requests/issues/3772
        if not 400 <= resp.status_code < 500:
            self._thread_local.num_401_calls = 1
            return resp

        if self._thread_local.pos is not None:
            # Rewind the file position indicator of the body to where
            # it was to resend the request.
            resp.request.body.seek(self._thread_local.pos)
        s_auth = resp.headers.get("www-authenticate", "")

        if "digest" in s_auth.lower() and self._thread_local.num_401_calls < 2:
            self._thread_local.num_401_calls += 1
            pat = re.compile(r"digest ", flags=re.IGNORECASE)
            self._thread_local.chal = parse_dict_header(pat.sub("", s_auth, count=1))

            # Consume content and release the original connection
            # to allow our new request to reuse the same one.
            # pylint: disable=pointless-statement
            resp.content
            # pylint: enable=pointless-statement
            resp.close()
            prep = resp.request.copy()
            # pylint: disable=protected-access
            extract_cookies_to_jar(prep._cookies, resp.request, resp.raw)
            prep.prepare_cookies(prep._cookies)
            # pylint: enable=protected-access

            prep.headers["Authorization"] = self.build_digest_header(
                prep.method, prep.url
            )
            new_resp = resp.connection.send(prep, **kwargs)
            new_resp.history.append(resp)
            new_resp.request = prep

            return new_resp

        self._thread_local.num_401_calls = 1
        return resp

    def __call__(self, req: Any) -> Any:
        """Apply digest authentication to the request."""
        # Initialize per-thread state, if needed
        self.init_per_thread_state()
        # If we have a saved nonce, skip the 401
        if self._thread_local.last_nonce:
            req.headers["Authorization"] = self.build_digest_header(req.method, req.url)
        try:
            self._thread_local.pos = req.body.tell()
        except AttributeError:
            # In the case of HTTPDigestAuth being reused and the body of
            # the previous request was a file-like object, pos has the
            # file position of the previous body. Ensure it's set to
            # None.
            self._thread_local.pos = None
        req.register_hook("response", self.handle_401)
        req.register_hook("response", self.handle_redirect)
        self._thread_local.num_401_calls = 1

        return req

    def __eq__(self, other: Any) -> bool:
        return all(
            [
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
            ]
        )

    def __ne__(self, other: Any) -> bool:
        return not self == other
