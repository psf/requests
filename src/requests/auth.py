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

from ._internal_utils import to_native_string
from .compat import basestring, str, urlparse
from .cookies import extract_cookies_to_jar
from .utils import parse_dict_header

CONTENT_TYPE_FORM_URLENCODED = "application/x-www-form-urlencoded"
CONTENT_TYPE_MULTI_PART = "multipart/form-data"


def _basic_auth_str(username, password):
    """
    Generates a Basic Authentication string for HTTP requests, compatible with the HTTP Basic Auth standard.
    
    This function is used internally by Requests to construct the Authorization header required for Basic Authentication, ensuring compatibility with servers expecting credentials in the format "Basic base64(username:password)". The function maintains backward compatibility by accepting non-string inputs (like integers) and converting them to strings, though this behavior is deprecated and will be removed in Requests 3.0.0.
    
    Args:
        username: The username for authentication, which may be any object but should be a string or bytes in future versions.
        password: The password for authentication, which may be any object but should be a string or bytes in future versions.
    
    Returns:
        A properly formatted Basic Auth string (e.g., "Basic dXNlcm5hbWU6cGFzc3dvcmQ=") suitable for inclusion in HTTP Authorization headers.
    """

    # "I want us to put a big-ol' comment on top of it that
    # says that this behaviour is dumb but we need to preserve
    # it because people are relying on it."
    #    - Lukasa
    #
    # These are here solely to maintain backwards compatibility
    # for things like ints. This will be removed in 3.0.0.
    if not isinstance(username, basestring):
        warnings.warn(
            "Non-string usernames will no longer be supported in Requests "
            "3.0.0. Please convert the object you've passed in ({!r}) to "
            "a string or bytes object in the near future to avoid "
            "problems.".format(username),
            category=DeprecationWarning,
        )
        username = str(username)

    if not isinstance(password, basestring):
        warnings.warn(
            "Non-string passwords will no longer be supported in Requests "
            "3.0.0. Please convert the object you've passed in ({!r}) to "
            "a string or bytes object in the near future to avoid "
            "problems.".format(type(password)),
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
    """
    Base class that all auth implementations derive from
    """


    def __call__(self, r):
        """
        Calls the authentication hook to modify the request before it's sent, enabling custom authentication logic.
        
        Args:
            r: The request object to be processed by the authentication hook, allowing modifications such as adding headers or credentials.
        """
        raise NotImplementedError("Auth hooks must be callable.")


class HTTPBasicAuth(AuthBase):
    """
    Attaches HTTP Basic Authentication to the given Request object.
    """


    def __init__(self, username, password):
        """
        Initializes a new authentication instance with the provided credentials for use in HTTP requests.
        
        Args:
            username: The username for authenticating with web services.
            password: The password for authenticating with web services.
        """
        self.username = username
        self.password = password

    def __eq__(self, other):
        """
        Compare this instance with another for equality based on username and password attributes, which is essential for consistent authentication state comparison across request sessions.
        
        Args:
            other: The object to compare against. If it lacks username or password attributes, they are treated as None.
        
        Returns:
            True if both username and password attributes are equal, False otherwise.
        """
        return all(
            [
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
            ]
        )

    def __ne__(self, other):
        """
        Compares this object with another to determine inequality, used for consistent object comparison in Requests' internal operations.
        
        Args:
            other: The object to compare against for inequality
        
        Returns:
            True if the objects are not equal, False otherwise; essential for reliable equality checks in request handling and session management
        """
        return not self == other

    def __call__(self, r):
        """
        Adds HTTP Basic Authentication to outgoing requests using stored credentials, enabling secure access to protected resources.
        
        Args:
            r: The request object to modify, expected to have a 'headers' attribute
        
        Returns:
            The modified request object with an Authorization header containing the Basic authentication credentials
        """
        r.headers["Authorization"] = _basic_auth_str(self.username, self.password)
        return r


class HTTPProxyAuth(HTTPBasicAuth):
    """
    Attaches HTTP Proxy Authentication to a given Request object.
    """


    def __call__(self, r):
        """
        Adds a Proxy-Authorization header with basic authentication to HTTP requests, enabling secure access to protected proxy servers. This supports the library's goal of simplifying authenticated HTTP interactions, particularly when routing requests through authenticated proxies.
        
        Args:
            r: The request object to modify, expected to have a 'headers' attribute
        
        Returns:
            The modified request object with the Proxy-Authorization header added
        """
        r.headers["Proxy-Authorization"] = _basic_auth_str(self.username, self.password)
        return r


class HTTPDigestAuth(AuthBase):
    """
    Attaches HTTP Digest Authentication to the given Request object.
    """


    def __init__(self, username, password):
        """
        Initializes a new authentication instance with the provided credentials, enabling secure HTTP requests through the Requests library.
        
        Args:
            username: The username for authenticating with the target server.
            password: The password for authenticating with the target server.
        """
        self.username = username
        self.password = password
        # Keep state in per-thread local storage
        self._thread_local = threading.local()

    def init_per_thread_state(self):
        """
        Initializes thread-local state for HTTP authentication tracking, ensuring each thread maintains isolated and consistent state for handling challenges, nonces, and 401 retry counts. This is critical in multi-threaded environments where concurrent requests may require independent authentication state management, preventing race conditions and ensuring accurate tracking of authentication attempts across threads.
        """
        # Ensure state is initialized just once per-thread
        if not hasattr(self._thread_local, "init"):
            self._thread_local.init = True
            self._thread_local.last_nonce = ""
            self._thread_local.nonce_count = 0
            self._thread_local.chal = {}
            self._thread_local.pos = None
            self._thread_local.num_401_calls = None

    def build_digest_header(self, method, url):
        """
        Builds a Digest authentication header for HTTP requests, enabling secure authentication with servers that support the Digest scheme. This function is part of Requests' authentication framework, allowing users to authenticate against protected resources without transmitting passwords in plain text, aligning with the library's goal of simplifying secure HTTP interactions.
        
        Args:
            method: The HTTP method (e.g., GET, POST) used in the request.
            url: The URL being requested, used to construct the request URI for the digest calculation.
        """

        realm = self._thread_local.chal["realm"]
        nonce = self._thread_local.chal["nonce"]
        qop = self._thread_local.chal.get("qop")
        algorithm = self._thread_local.chal.get("algorithm")
        opaque = self._thread_local.chal.get("opaque")
        hash_utf8 = None

        if algorithm is None:
            _algorithm = "MD5"
        else:
            _algorithm = algorithm.upper()
        # lambdas assume digest modules are imported at the top level
        if _algorithm == "MD5" or _algorithm == "MD5-SESS":

            def md5_utf8(x):
                if isinstance(x, str):
                    x = x.encode("utf-8")
                return hashlib.md5(x).hexdigest()

            hash_utf8 = md5_utf8
        elif _algorithm == "SHA":

            def sha_utf8(x):
                if isinstance(x, str):
                    x = x.encode("utf-8")
                return hashlib.sha1(x).hexdigest()

            hash_utf8 = sha_utf8
        elif _algorithm == "SHA-256":

            def sha256_utf8(x):
                if isinstance(x, str):
                    x = x.encode("utf-8")
                return hashlib.sha256(x).hexdigest()

            hash_utf8 = sha256_utf8
        elif _algorithm == "SHA-512":

            def sha512_utf8(x):
                if isinstance(x, str):
                    x = x.encode("utf-8")
                return hashlib.sha512(x).hexdigest()

            hash_utf8 = sha512_utf8

        KD = lambda s, d: hash_utf8(f"{s}:{d}")  # noqa:E731

        if hash_utf8 is None:
            return None

        # XXX not implemented yet
        entdig = None
        p_parsed = urlparse(url)
        #: path is request-uri defined in RFC 2616 which should not be empty
        path = p_parsed.path or "/"
        if p_parsed.query:
            path += f"?{p_parsed.query}"

        A1 = f"{self.username}:{realm}:{self.password}"
        A2 = f"{method}:{path}"

        HA1 = hash_utf8(A1)
        HA2 = hash_utf8(A2)

        if nonce == self._thread_local.last_nonce:
            self._thread_local.nonce_count += 1
        else:
            self._thread_local.nonce_count = 1
        ncvalue = f"{self._thread_local.nonce_count:08x}"
        s = str(self._thread_local.nonce_count).encode("utf-8")
        s += nonce.encode("utf-8")
        s += time.ctime().encode("utf-8")
        s += os.urandom(8)

        cnonce = hashlib.sha1(s).hexdigest()[:16]
        if _algorithm == "MD5-SESS":
            HA1 = hash_utf8(f"{HA1}:{nonce}:{cnonce}")

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
        if entdig:
            base += f', digest="{entdig}"'
        if qop:
            base += f', qop="auth", nc={ncvalue}, cnonce="{cnonce}"'

        return f"Digest {base}"

    def handle_redirect(self, r, **kwargs):
        """
        Reset the 401 retry counter when a redirect occurs to prevent unnecessary authentication retries.
        
        Redirects can indicate a change in the request path or server configuration, which may require fresh authentication. By resetting the counter, the library ensures that subsequent requests are not blocked due to outdated retry state, maintaining reliable authentication flow during redirect chains.
        
        Args:
            r: The response object being processed, used to determine if it's a redirect.
        """
        if r.is_redirect:
            self._thread_local.num_401_calls = 1

    def handle_401(self, r, **kwargs):
        """
        Handles HTTP 401 Unauthorized responses by attempting digest authentication when necessary.
        
        When a request receives a 401 response, this function checks if the server requires digest authentication. If so, it retries the request with the appropriate Authorization header, preserving the original request's state such as cookies and body position. This enables seamless authentication without requiring manual intervention, aligning with Requests' goal of simplifying HTTP interactions and supporting automatic authentication for web services.
        
        Args:
            r: The original response object that triggered the 401 status
            **kwargs: Additional arguments passed to the connection send method
        
        Returns:
            The updated response from the retry attempt, or the original response if no authentication was needed or applicable
        """

        # If response is not 4xx, do not auth
        # See https://github.com/psf/requests/issues/3772
        if not 400 <= r.status_code < 500:
            self._thread_local.num_401_calls = 1
            return r

        if self._thread_local.pos is not None:
            # Rewind the file position indicator of the body to where
            # it was to resend the request.
            r.request.body.seek(self._thread_local.pos)
        s_auth = r.headers.get("www-authenticate", "")

        if "digest" in s_auth.lower() and self._thread_local.num_401_calls < 2:
            self._thread_local.num_401_calls += 1
            pat = re.compile(r"digest ", flags=re.IGNORECASE)
            self._thread_local.chal = parse_dict_header(pat.sub("", s_auth, count=1))

            # Consume content and release the original connection
            # to allow our new request to reuse the same one.
            r.content
            r.close()
            prep = r.request.copy()
            extract_cookies_to_jar(prep._cookies, r.request, r.raw)
            prep.prepare_cookies(prep._cookies)

            prep.headers["Authorization"] = self.build_digest_header(
                prep.method, prep.url
            )
            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep

            return _r

        self._thread_local.num_401_calls = 1
        return r

    def __call__(self, r):
        """
        Applies HTTP Digest Authentication to a request by adding authentication headers and registering response hooks to handle 401 challenges and redirects.
        
        This enables secure, stateful authentication with servers that require digest authentication, ensuring requests are automatically re-attempted with valid credentials when challenged. It's part of Requests' broader support for authentication mechanisms, allowing seamless integration with protected web services.
        
        Args:
            r: The request object to which authentication and hooks will be applied.
        
        Returns:
            The modified request object with authentication headers and response hooks registered.
        """
        # Initialize per-thread state, if needed
        self.init_per_thread_state()
        # If we have a saved nonce, skip the 401
        if self._thread_local.last_nonce:
            r.headers["Authorization"] = self.build_digest_header(r.method, r.url)
        try:
            self._thread_local.pos = r.body.tell()
        except AttributeError:
            # In the case of HTTPDigestAuth being reused and the body of
            # the previous request was a file-like object, pos has the
            # file position of the previous body. Ensure it's set to
            # None.
            self._thread_local.pos = None
        r.register_hook("response", self.handle_401)
        r.register_hook("response", self.handle_redirect)
        self._thread_local.num_401_calls = 1

        return r

    def __eq__(self, other):
        """
        Compares two authentication instances for equality by checking if their username and password attributes match.
        
        This comparison is used to determine if two authentication objects represent the same credentials, which is essential for consistent authentication handling across requests, especially when validating or caching credentials in session-based workflows.
        
        Args:
            other: The other instance to compare against for equality
        
        Returns:
            True if both instances have matching username and password values, False otherwise
        """
        return all(
            [
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
            ]
        )

    def __ne__(self, other):
        """
        Compares this object with another to determine inequality, used for consistent object comparison in Requests' HTTP-related classes.
        
        Args:
            other: The object to compare against for inequality
        
        Returns:
            Boolean indicating whether the objects are not equal, enabling reliable equality checks across Requests' request and response objects
        """
        return not self == other
