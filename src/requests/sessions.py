"""
requests.sessions
~~~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
requests (cookies, auth, proxies).
"""
import os
import sys
import time
from collections import OrderedDict
from datetime import timedelta

from ._internal_utils import to_native_string
from .adapters import HTTPAdapter
from .auth import _basic_auth_str
from .compat import Mapping, cookielib, urljoin, urlparse
from .cookies import (
    RequestsCookieJar,
    cookiejar_from_dict,
    extract_cookies_to_jar,
    merge_cookies,
)
from .exceptions import (
    ChunkedEncodingError,
    ContentDecodingError,
    InvalidSchema,
    TooManyRedirects,
)
from .hooks import default_hooks, dispatch_hook

# formerly defined here, reexposed here for backward compatibility
from .models import (  # noqa: F401
    DEFAULT_REDIRECT_LIMIT,
    REDIRECT_STATI,
    PreparedRequest,
    Request,
)
from .status_codes import codes
from .structures import CaseInsensitiveDict
from .utils import (  # noqa: F401
    DEFAULT_PORTS,
    default_headers,
    get_auth_from_url,
    get_environ_proxies,
    get_netrc_auth,
    requote_uri,
    resolve_proxies,
    rewind_body,
    should_bypass_proxies,
    to_key_val_list,
)

# Preferred clock, based on which one is more accurate on a given system.
if sys.platform == "win32":
    preferred_clock = time.perf_counter
else:
    preferred_clock = time.time


def merge_setting(request_setting, session_setting, dict_class=OrderedDict):
    """
    Merges request-specific settings with session-level defaults, prioritizing explicit request settings while preserving session configurations. This ensures consistent and predictable behavior across requests by combining user-defined overrides with default session values, particularly useful for managing configuration like headers, cookies, or authentication settings in a structured way.
    
    Args:
        request_setting: The setting explicitly defined for the current request, which may override session defaults.
        session_setting: The default setting from the session, used as a baseline when no request-specific value is provided.
        dict_class: The dictionary class used to construct the merged result (default: OrderedDict), ensuring order preservation if needed.
    
    Returns:
        A merged dictionary of settings with request-level values taking precedence, where keys set to None are removed to avoid unintended side effects.
    """

    if session_setting is None:
        return request_setting

    if request_setting is None:
        return session_setting

    # Bypass if not a dictionary (e.g. verify)
    if not (
        isinstance(session_setting, Mapping) and isinstance(request_setting, Mapping)
    ):
        return request_setting

    merged_setting = dict_class(to_key_val_list(session_setting))
    merged_setting.update(to_key_val_list(request_setting))

    # Remove keys that are set to None. Extract keys first to avoid altering
    # the dictionary during iteration.
    none_keys = [k for (k, v) in merged_setting.items() if v is None]
    for key in none_keys:
        del merged_setting[key]

    return merged_setting


def merge_hooks(request_hooks, session_hooks, dict_class=OrderedDict):
    """
    Merges request-level hooks with session-level hooks while preserving session hooks when request hooks are empty.
    
    This ensures that session-level hooks (such as response processing) remain active even when request-level hooks are explicitly set to an empty list, preventing unintended loss of functionality. This is critical in Requests' session management model, where session hooks provide default behavior across multiple requests, and their integrity must be maintained.
    
    Args:
        request_hooks: Hooks defined at the request level, which may be None or contain empty lists.
        session_hooks: Hooks defined at the session level, which serve as defaults for multiple requests.
        dict_class: Class used to construct the merged dictionary, preserving order if needed.
    
    Returns:
        A merged dictionary of hooks, prioritizing request hooks while ensuring session hooks are not lost when request hooks are empty.
    """
    if session_hooks is None or session_hooks.get("response") == []:
        return request_hooks

    if request_hooks is None or request_hooks.get("response") == []:
        return session_hooks

    return merge_setting(request_hooks, session_hooks, dict_class)


class SessionRedirectMixin:
    """
    Mixin to handle redirection logic for HTTP sessions, including managing authentication, proxies, and request methods during redirects.
    
        This class provides methods to intelligently manage HTTP redirects by adjusting authentication headers, proxy configurations, and request methods based on redirect targets and environment settings.
    
        Class Methods:
        - get_redirect_target:
    """

    def get_redirect_target(self, resp):
        """
        Extracts the redirect target from an HTTP response, handling encoding issues that may arise with UTF-8 encoded location headers.
        
        Args:
            resp: The HTTP response object containing the redirect information, typically from a 3xx status code response.
        """
        # Due to the nature of how requests processes redirects this method will
        # be called at least once upon the original response and at least twice
        # on each subsequent redirect response (if any).
        # If a custom mixin is used to handle this logic, it may be advantageous
        # to cache the redirect location onto the response object as a private
        # attribute.
        if resp.is_redirect:
            location = resp.headers["location"]
            # Currently the underlying http module on py3 decode headers
            # in latin1, but empirical evidence suggests that latin1 is very
            # rarely used with non-ASCII characters in HTTP headers.
            # It is more likely to get UTF8 header rather than latin1.
            # This causes incorrect handling of UTF8 encoded location headers.
            # To solve this, we re-encode the location in latin1.
            location = location.encode("latin1")
            return to_native_string(location, "utf8")
        return None

    def should_strip_auth(self, old_url, new_url):
        """
        Determine whether the Authorization header should be stripped during HTTP redirects to prevent potential security leaks when moving between different hosts or schemes.
        
        This function enforces security best practices by removing authentication credentials in redirect scenarios where the target host or scheme changes, reducing the risk of exposing sensitive credentials. It maintains backward compatibility with older versions of Requests for common http->https redirects on standard ports, while still protecting against unintended credential leakage in other cases.
        
        Args:
            old_url: The original URL before redirection
            new_url: The destination URL after redirection
        
        Returns:
            True if the Authorization header should be removed, False otherwise
        """
        old_parsed = urlparse(old_url)
        new_parsed = urlparse(new_url)
        if old_parsed.hostname != new_parsed.hostname:
            return True
        # Special case: allow http -> https redirect when using the standard
        # ports. This isn't specified by RFC 7235, but is kept to avoid
        # breaking backwards compatibility with older versions of requests
        # that allowed any redirects on the same host.
        if (
            old_parsed.scheme == "http"
            and old_parsed.port in (80, None)
            and new_parsed.scheme == "https"
            and new_parsed.port in (443, None)
        ):
            return False

        # Handle default port usage corresponding to scheme.
        changed_port = old_parsed.port != new_parsed.port
        changed_scheme = old_parsed.scheme != new_parsed.scheme
        default_port = (DEFAULT_PORTS.get(old_parsed.scheme, None), None)
        if (
            not changed_scheme
            and old_parsed.port in default_port
            and new_parsed.port in default_port
        ):
            return False

        # Standard case: root URI must match
        return changed_port or changed_scheme

    def resolve_redirects(
        self,
        resp,
        req,
        stream=False,
        timeout=None,
        verify=True,
        cert=None,
        proxies=None,
        yield_requests=False,
        **adapter_kwargs,
    ):
        """
        Follows HTTP redirects automatically, maintaining request state and cookies across redirects. This function enables seamless navigation through redirect chains while preserving session data, which is essential for reliable web scraping and API interactions in the Requests library.
        
        Args:
            resp: The initial HTTP response containing a redirect (e.g., 301, 302) to follow.
            req: The original request that led to the redirect, used as a template for subsequent requests.
            stream: Whether to stream the response body, useful for large downloads.
            timeout: Optional timeout for the request, preventing indefinite waits.
            verify: Whether to verify SSL certificates, ensuring secure connections.
            cert: Optional client certificate for authentication.
            proxies: Optional dictionary of proxy settings for routing requests.
            yield_requests: If True, yields the prepared requests instead of responses, enabling inspection or modification.
            adapter_kwargs: Additional arguments passed to the adapter for sending requests.
        """

        hist = []  # keep track of history

        url = self.get_redirect_target(resp)
        previous_fragment = urlparse(req.url).fragment
        while url:
            prepared_request = req.copy()

            # Update history and keep track of redirects.
            # resp.history must ignore the original request in this loop
            hist.append(resp)
            resp.history = hist[1:]

            try:
                resp.content  # Consume socket so it can be released
            except (ChunkedEncodingError, ContentDecodingError, RuntimeError):
                resp.raw.read(decode_content=False)

            if len(resp.history) >= self.max_redirects:
                raise TooManyRedirects(
                    f"Exceeded {self.max_redirects} redirects.", response=resp
                )

            # Release the connection back into the pool.
            resp.close()

            # Handle redirection without scheme (see: RFC 1808 Section 4)
            if url.startswith("//"):
                parsed_rurl = urlparse(resp.url)
                url = ":".join([to_native_string(parsed_rurl.scheme), url])

            # Normalize url case and attach previous fragment if needed (RFC 7231 7.1.2)
            parsed = urlparse(url)
            if parsed.fragment == "" and previous_fragment:
                parsed = parsed._replace(fragment=previous_fragment)
            elif parsed.fragment:
                previous_fragment = parsed.fragment
            url = parsed.geturl()

            # Facilitate relative 'location' headers, as allowed by RFC 7231.
            # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
            # Compliant with RFC3986, we percent encode the url.
            if not parsed.netloc:
                url = urljoin(resp.url, requote_uri(url))
            else:
                url = requote_uri(url)

            prepared_request.url = to_native_string(url)

            self.rebuild_method(prepared_request, resp)

            # https://github.com/psf/requests/issues/1084
            if resp.status_code not in (
                codes.temporary_redirect,
                codes.permanent_redirect,
            ):
                # https://github.com/psf/requests/issues/3490
                purged_headers = ("Content-Length", "Content-Type", "Transfer-Encoding")
                for header in purged_headers:
                    prepared_request.headers.pop(header, None)
                prepared_request.body = None

            headers = prepared_request.headers
            headers.pop("Cookie", None)

            # Extract any cookies sent on the response to the cookiejar
            # in the new request. Because we've mutated our copied prepared
            # request, use the old one that we haven't yet touched.
            extract_cookies_to_jar(prepared_request._cookies, req, resp.raw)
            merge_cookies(prepared_request._cookies, self.cookies)
            prepared_request.prepare_cookies(prepared_request._cookies)

            # Rebuild auth and proxy information.
            proxies = self.rebuild_proxies(prepared_request, proxies)
            self.rebuild_auth(prepared_request, resp)

            # A failed tell() sets `_body_position` to `object()`. This non-None
            # value ensures `rewindable` will be True, allowing us to raise an
            # UnrewindableBodyError, instead of hanging the connection.
            rewindable = prepared_request._body_position is not None and (
                "Content-Length" in headers or "Transfer-Encoding" in headers
            )

            # Attempt to rewind consumed file-like object.
            if rewindable:
                rewind_body(prepared_request)

            # Override the original request.
            req = prepared_request

            if yield_requests:
                yield req
            else:
                resp = self.send(
                    req,
                    stream=stream,
                    timeout=timeout,
                    verify=verify,
                    cert=cert,
                    proxies=proxies,
                    allow_redirects=False,
                    **adapter_kwargs,
                )

                extract_cookies_to_jar(self.cookies, prepared_request, resp.raw)

                # extract redirect url, if any, for the next loop
                url = self.get_redirect_target(resp)
                yield resp

    def rebuild_auth(self, prepared_request, response):
        """
        When following redirects, this method ensures authentication credentials are handled securely by stripping them when moving to a different host to prevent leakage. It then reapplies appropriate authentication—such as from .netrc—on the new host to maintain access without exposing credentials.
        
        Args:
            prepared_request: The request object being processed, which may contain authentication headers to be adjusted.
            response: The response that triggered the redirect, used to determine if authentication should be stripped based on URL changes.
        """
        headers = prepared_request.headers
        url = prepared_request.url

        if "Authorization" in headers and self.should_strip_auth(
            response.request.url, url
        ):
            # If we get redirected to a new host, we should strip out any
            # authentication headers.
            del headers["Authorization"]

        # .netrc might have more auth for us on our new host.
        new_auth = get_netrc_auth(url) if self.trust_env else None
        if new_auth is not None:
            prepared_request.prepare_auth(new_auth)

    def rebuild_proxies(self, prepared_request, proxies):
        """
        Re-evaluates and updates proxy settings based on environment variables and the current request context, ensuring secure and correct proxy configuration during redirects. This is critical for maintaining compliance with NO_PROXY settings and preventing unauthorized proxy access, especially in HTTPS scenarios where Proxy-Authorization headers could be leaked.
        
        Args:
            prepared_request: The request object containing URL and headers to evaluate
            proxies: Current proxy configuration to potentially update
        
        Returns:
            Updated proxy configuration dictionary reflecting environment rules and security best practices
        """
        headers = prepared_request.headers
        scheme = urlparse(prepared_request.url).scheme
        new_proxies = resolve_proxies(prepared_request, proxies, self.trust_env)

        if "Proxy-Authorization" in headers:
            del headers["Proxy-Authorization"]

        try:
            username, password = get_auth_from_url(new_proxies[scheme])
        except KeyError:
            username, password = None, None

        # urllib3 handles proxy authorization for us in the standard adapter.
        # Avoid appending this to TLS tunneled requests where it may be leaked.
        if not scheme.startswith("https") and username and password:
            headers["Proxy-Authorization"] = _basic_auth_str(username, password)

        return new_proxies

    def rebuild_method(self, prepared_request, response):
        """
        Adjusts the HTTP method of a request during redirects to align with browser behavior and HTTP specifications.
        
        This ensures consistent and expected behavior when following redirects, particularly for POST requests that should be converted to GETs under certain conditions (e.g., 301, 302, or 303 responses). This mimics how web browsers handle redirects, improving compatibility with web servers and APIs that expect specific method changes during redirection.
        
        Args:
            prepared_request: The request object being processed, whose method may be updated.
            response: The response that triggered the redirect, containing status code and other metadata.
        """
        method = prepared_request.method

        # https://tools.ietf.org/html/rfc7231#section-6.4.4
        if response.status_code == codes.see_other and method != "HEAD":
            method = "GET"

        # Do what the browsers do, despite standards...
        # First, turn 302s into GETs.
        if response.status_code == codes.found and method != "HEAD":
            method = "GET"

        # Second, if a POST is responded to with a 301, turn it into a GET.
        # This bizarre behaviour is explained in Issue 1704.
        if response.status_code == codes.moved and method == "POST":
            method = "GET"

        prepared_request.method = method


class Session(SessionRedirectMixin):
    """
    A persistent HTTP session that maintains settings, cookies, and authentication across multiple requests, enabling efficient and consistent interaction with web services.
    
        Provides cookie persistence, connection-pooling, and configuration.
    
        Basic Usage::
    
          >>> import requests
          >>> s = requests.Session()
          >>> s.get('https://httpbin.org/get')
          <Response [200]>
    
        Or as a context manager::
    
          >>> with requests.Session() as s:
          ...     s.get('https://httpbin.org/get')
          <Response [200]>
    """


    __attrs__ = [
        "headers",
        "cookies",
        "auth",
        "proxies",
        "hooks",
        "params",
        "verify",
        "cert",
        "adapters",
        "stream",
        "trust_env",
        "max_redirects",
    ]

    def __init__(self):
        """
        Initialize a new Session object to manage persistent HTTP settings and state across multiple requests, enabling efficient and consistent interaction with web services.
        
        Sessions in Requests are designed to maintain shared configuration—such as headers, authentication, proxies, cookies, and SSL settings—across repeated requests, reducing boilerplate and improving performance. This is particularly useful for interacting with APIs or websites requiring authentication, session tracking, or consistent request behavior. By default, the session enforces security best practices (e.g., SSL verification, reasonable redirect limits) while providing flexibility through configurable options, making it ideal for both development and production use cases.
        """
        #: A case-insensitive dictionary of headers to be sent on each
        #: :class:`Request <Request>` sent from this
        #: :class:`Session <Session>`.
        self.headers = default_headers()

        #: Default Authentication tuple or object to attach to
        #: :class:`Request <Request>`.
        self.auth = None

        #: Dictionary mapping protocol or protocol and host to the URL of the proxy
        #: (e.g. {'http': 'foo.bar:3128', 'http://host.name': 'foo.bar:4012'}) to
        #: be used on each :class:`Request <Request>`.
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
        #: Defaults to `True`, requiring requests to verify the TLS certificate at the
        #: remote end.
        #: If verify is set to `False`, requests will accept any TLS certificate
        #: presented by the server, and will ignore hostname mismatches and/or
        #: expired certificates, which will make your application vulnerable to
        #: man-in-the-middle (MitM) attacks.
        #: Only set this to `False` for testing.
        self.verify = True

        #: SSL client certificate default, if String, path to ssl client
        #: cert file (.pem). If Tuple, ('cert', 'key') pair.
        self.cert = None

        #: Maximum number of redirects allowed. If the request exceeds this
        #: limit, a :class:`TooManyRedirects` exception is raised.
        #: This defaults to requests.models.DEFAULT_REDIRECT_LIMIT, which is
        #: 30.
        self.max_redirects = DEFAULT_REDIRECT_LIMIT

        #: Trust environment settings for proxy configuration, default
        #: authentication and similar.
        self.trust_env = True

        #: A CookieJar containing all currently outstanding cookies set on this
        #: session. By default it is a
        #: :class:`RequestsCookieJar <requests.cookies.RequestsCookieJar>`, but
        #: may be any other ``cookielib.CookieJar`` compatible object.
        self.cookies = cookiejar_from_dict({})

        # Default connection adapters.
        self.adapters = OrderedDict()
        self.mount("https://", HTTPAdapter())
        self.mount("http://", HTTPAdapter())

    def __enter__(self):
        """
        Enter the runtime context to enable use of this object in `with` statements, allowing for automatic resource management.
        
        Returns:
            The instance itself, enabling clean, context-aware usage in `with` blocks for consistent request handling and resource cleanup.
        """
        return self

    def __exit__(self, *args):
        """
        Exit the context manager and close the underlying connection resource.
        
        Args:
            args: Exception information passed by the context manager protocol, including exception type, value, and traceback. If an exception occurred within the with block, this allows the context manager to handle it appropriately; otherwise, it remains empty.
        """
        self.close()

    def prepare_request(self, request):
        """
        Constructs a prepared HTTP request by merging the provided request's settings with session-level configurations, enabling consistent and reusable HTTP interactions across multiple requests.
        
        This function is essential for maintaining session state—such as cookies, authentication, and default headers—while allowing individual requests to override or extend these settings. It ensures that all request components are properly merged and normalized before transmission, which is critical for reliable and predictable HTTP communication.
        
        Args:
            request: The Request object to prepare, containing method, URL, headers, and other request-specific data.
        
        Returns:
            A PreparedRequest instance ready for transmission, with all settings merged from both the request and session context.
        """
        cookies = request.cookies or {}

        # Bootstrap CookieJar.
        if not isinstance(cookies, cookielib.CookieJar):
            cookies = cookiejar_from_dict(cookies)

        # Merge with session cookies
        merged_cookies = merge_cookies(
            merge_cookies(RequestsCookieJar(), self.cookies), cookies
        )

        # Set environment's basic authentication if not explicitly set.
        auth = request.auth
        if self.trust_env and not auth and not self.auth:
            auth = get_netrc_auth(request.url)

        p = PreparedRequest()
        p.prepare(
            method=request.method.upper(),
            url=request.url,
            files=request.files,
            data=request.data,
            json=request.json,
            headers=merge_setting(
                request.headers, self.headers, dict_class=CaseInsensitiveDict
            ),
            params=merge_setting(request.params, self.params),
            auth=merge_setting(auth, self.auth),
            cookies=merged_cookies,
            hooks=merge_hooks(request.hooks, self.hooks),
        )
        return p

    def request(
        self,
        method,
        url,
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
        cert=None,
        json=None,
    ):
        """
        Sends an HTTP request using the specified method and parameters, handling request preparation, authentication, and response processing. This function is the core interface for making HTTP requests in the Requests library, abstracting away low-level details to provide a simple, intuitive API for interacting with web services.
        
        Args:
            method: The HTTP method (e.g., GET, POST) to use for the request.
            url: The URL to send the request to.
            params: Optional dictionary or bytes to include in the URL query string.
            data: Optional data to send in the request body, such as form data or raw bytes.
            json: Optional JSON data to send in the request body (automatically serialized).
            headers: Optional dictionary of HTTP headers to include in the request.
            cookies: Optional dictionary or CookieJar object to send with the request.
            files: Optional dictionary mapping filenames to file-like objects for multipart encoding.
            auth: Optional authentication tuple or callable for HTTP authentication.
            timeout: Optional timeout value for the request, either as a float or a (connect, read) tuple.
            allow_redirects: Whether to automatically follow HTTP redirects (default is True).
            proxies: Optional dictionary mapping protocols to proxy URLs.
            hooks: Optional dictionary mapping event hooks to callable functions.
            stream: Whether to immediately download the response content (default is False).
            verify: Whether to verify SSL certificates (True by default); can also be a path to a CA bundle.
            cert: Optional SSL client certificate, either a path to a file or a tuple of (cert, key) files.
        
        Returns:
            A Response object containing the server's response, including status code, headers, and content.
        """
        # Create the Request.
        req = Request(
            method=method.upper(),
            url=url,
            headers=headers,
            files=files,
            data=data or {},
            json=json,
            params=params or {},
            auth=auth,
            cookies=cookies,
            hooks=hooks,
        )
        prep = self.prepare_request(req)

        proxies = proxies or {}

        settings = self.merge_environment_settings(
            prep.url, proxies, stream, verify, cert
        )

        # Send the request.
        send_kwargs = {
            "timeout": timeout,
            "allow_redirects": allow_redirects,
        }
        send_kwargs.update(settings)
        resp = self.send(prep, **send_kwargs)

        return resp

    def get(self, url, **kwargs):
        """
        Sends an HTTP GET request to the specified URL, making it easy to retrieve data from web services or APIs. This function is central to Requests' purpose of providing a simple, intuitive interface for HTTP interactions, abstracting away low-level details so developers can focus on consuming web content efficiently.
        
        Args:
            url: The URL to send the GET request to.
            **kwargs: Additional arguments to pass to the underlying request method, such as headers, parameters, or authentication settings.
        
        Returns:
            A Response object containing the server's response, including status code, headers, and response body, enabling easy access to the requested data.
        """
        r"""Sends a GET request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault("allow_redirects", True)
        return self.request("GET", url, **kwargs)

    def options(self, url, **kwargs):
        """
        Sends an HTTP OPTIONS request to discover the communication options available for a given URL, such as supported methods and headers. This is particularly useful for debugging APIs, testing CORS configurations, or dynamically determining how to interact with a web service.
        
        Args:
            url: The URL to send the OPTIONS request to.
            **kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeout settings.
        
        Returns:
            A Response object containing the server's response, including status code, headers, and body, which can be used to inspect available HTTP methods and other server capabilities.
        """
        r"""Sends a OPTIONS request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault("allow_redirects", True)
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url, **kwargs):
        """
        Sends an HTTP HEAD request to retrieve resource metadata without downloading the body, which is useful for checking resource availability, size, or modification time efficiently.
        
        Args:
            url: The URL to send the HEAD request to.
            **kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeout settings.
        
        Returns:
            A Response object containing the server's response headers and status code, enabling inspection of resource metadata without transferring the full response body.
        """
        r"""Sends a HEAD request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        """
        Sends an HTTP POST request to the specified URL, enabling easy interaction with web APIs and services. This function is central to Requests' purpose of simplifying HTTP communication by providing a clean, intuitive interface for sending data to servers, supporting various data formats like form data, JSON, and file uploads.
        
        Args:
            url: The target URL for the POST request.
            data: Optional data to send in the request body, such as form data or raw bytes.
            json: Optional JSON data to send in the request body, automatically serialized.
            **kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeouts.
        
        Returns:
            A Response object containing the server's response, including status code, headers, and content.
        """
        r"""Sends a POST request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, list of tuples, bytes, or file-like
            object to send in the body of the :class:`Request`.
        :param json: (optional) json to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return self.request("POST", url, data=data, json=json, **kwargs)

    def put(self, url, data=None, **kwargs):
        """
        Sends an HTTP PUT request to update or replace a resource on the server. This method is essential for API interactions where data needs to be sent to a specific endpoint to modify existing resources, aligning with Requests' goal of providing a simple, intuitive interface for HTTP operations.
        
        Args:
            url: The URL of the resource to update.
            data: Optional data to send in the request body, such as a dictionary, list of tuples, bytes, or file-like object.
            **kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeout settings.
        
        Returns:
            A Response object containing the server's response to the PUT request, including status code, headers, and response body.
        """
        r"""Sends a PUT request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, list of tuples, bytes, or file-like
            object to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return self.request("PUT", url, data=data, **kwargs)

    def patch(self, url, data=None, **kwargs):
        """
        Sends an HTTP PATCH request to update resources on a server, enabling partial updates to existing data. This method is essential for RESTful API interactions where only specific fields need to be modified without replacing the entire resource.
        
        Args:
            url: The URL of the resource to update.
            data: Optional data to send in the request body, such as a dictionary, list of tuples, bytes, or file-like object.
            **kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeout settings.
        
        Returns:
            A Response object containing the server's response to the PATCH request, including status code, headers, and response body.
        """
        r"""Sends a PATCH request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, list of tuples, bytes, or file-like
            object to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return self.request("PATCH", url, data=data, **kwargs)

    def delete(self, url, **kwargs):
        """
        Sends an HTTP DELETE request to the specified URL to remove a resource from the server.
        
        This method is part of Requests' high-level API, designed to simplify HTTP interactions by providing intuitive, readable syntax for common operations. It abstracts away low-level details like connection handling and header management, allowing developers to focus on interacting with web services and APIs efficiently.
        
        Args:
            url: The URL of the resource to delete.
            kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeout settings.
        
        Returns:
            A Response object containing the server's response to the DELETE request, including status code, headers, and response body.
        """
        r"""Sends a DELETE request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return self.request("DELETE", url, **kwargs)

    def send(self, request, **kwargs):
        """
        Send a prepared HTTP request using the appropriate adapter and handle redirects, hooks, and cookies.
        
        This function is the core of Requests' request dispatching logic, responsible for executing an HTTP request with proper configuration, managing response processing, and ensuring consistent behavior across redirects and hooks. It leverages the session's settings (like stream, verify, cert, and proxies) and resolves any necessary redirects while preserving cookies and invoking response hooks.
        
        Args:
            request: A PreparedRequest object to send.
            **kwargs: Additional arguments to pass to the adapter, such as allow_redirects, stream, or hooks.
        
        Returns:
            The response object containing the server's response, including content, status code, headers, and any redirect history if applicable.
        """
        # Set defaults that the hooks can utilize to ensure they always have
        # the correct parameters to reproduce the previous request.
        kwargs.setdefault("stream", self.stream)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("cert", self.cert)
        if "proxies" not in kwargs:
            kwargs["proxies"] = resolve_proxies(request, self.proxies, self.trust_env)

        # It's possible that users might accidentally send a Request object.
        # Guard against that specific failure case.
        if isinstance(request, Request):
            raise ValueError("You can only send PreparedRequests.")

        # Set up variables needed for resolve_redirects and dispatching of hooks
        allow_redirects = kwargs.pop("allow_redirects", True)
        stream = kwargs.get("stream")
        hooks = request.hooks

        # Get the appropriate adapter to use
        adapter = self.get_adapter(url=request.url)

        # Start time (approximately) of the request
        start = preferred_clock()

        # Send the request
        r = adapter.send(request, **kwargs)

        # Total elapsed time of the request (approximately)
        elapsed = preferred_clock() - start
        r.elapsed = timedelta(seconds=elapsed)

        # Response manipulation hooks
        r = dispatch_hook("response", hooks, r, **kwargs)

        # Persist cookies
        if r.history:
            # If the hooks create history then we want those cookies too
            for resp in r.history:
                extract_cookies_to_jar(self.cookies, resp.request, resp.raw)

        extract_cookies_to_jar(self.cookies, request, r.raw)

        # Resolve redirects if allowed.
        if allow_redirects:
            # Redirect resolving generator.
            gen = self.resolve_redirects(r, request, **kwargs)
            history = [resp for resp in gen]
        else:
            history = []

        # Shuffle things around if there's history.
        if history:
            # Insert the first (original) request at the start
            history.insert(0, r)
            # Get the last request made
            r = history.pop()
            r.history = history

        # If redirects aren't being followed, store the response on the Request for Response.next().
        if not allow_redirects:
            try:
                r._next = next(
                    self.resolve_redirects(r, request, yield_requests=True, **kwargs)
                )
            except StopIteration:
                pass

        if not stream:
            r.content

        return r

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        """
        Merge environment variables and configuration settings into request parameters, ensuring consistent behavior across different environments.
        
        Args:
            url: The URL to which the request is made, used to determine proxy settings.
            proxies: Dictionary of proxy configurations, potentially overridden by environment variables.
            stream: Flag indicating whether to stream the response, merged with global stream setting.
            verify: SSL verification option, potentially derived from environment variables like REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE.
            cert: Client certificate configuration, merged with any global certificate settings.
        
        Returns:
            A dictionary containing the final merged settings for proxies, streaming, SSL verification, and client certificates, enabling requests to respect both user preferences and system-wide environment configurations.
        """
        # Gather clues from the surrounding environment.
        if self.trust_env:
            # Set environment's proxies.
            no_proxy = proxies.get("no_proxy") if proxies is not None else None
            env_proxies = get_environ_proxies(url, no_proxy=no_proxy)
            for k, v in env_proxies.items():
                proxies.setdefault(k, v)

            # Look for requests environment configuration
            # and be compatible with cURL.
            if verify is True or verify is None:
                verify = (
                    os.environ.get("REQUESTS_CA_BUNDLE")
                    or os.environ.get("CURL_CA_BUNDLE")
                    or verify
                )

        # Merge all the kwargs.
        proxies = merge_setting(proxies, self.proxies)
        stream = merge_setting(stream, self.stream)
        verify = merge_setting(verify, self.verify)
        cert = merge_setting(cert, self.cert)

        return {"proxies": proxies, "stream": stream, "verify": verify, "cert": cert}

    def get_adapter(self, url):
        """
        Returns the appropriate connection adapter for the given URL to handle HTTP requests efficiently.
        
        The function determines which adapter should manage the connection based on the URL's scheme or prefix, enabling Requests to support multiple protocols (like http, https, or custom schemes) through pluggable adapters. This design allows the library to be extensible and flexible when interacting with different types of web services.
        
        Args:
            url: The URL for which to find a matching connection adapter.
        
        Returns:
            The connection adapter that should handle the request for the given URL.
        """
        for prefix, adapter in self.adapters.items():
            if url.lower().startswith(prefix.lower()):
                return adapter

        # Nothing matches :-/
        raise InvalidSchema(f"No connection adapters were found for {url!r}")

    def close(self):
        """
        Closes all underlying adapters, terminating active connections and cleanly shutting down the session.
        
        This ensures proper cleanup of network resources after use, preventing connection leaks and maintaining the reliability of HTTP operations in long-running applications or when making multiple requests across different sessions.
        """
        for v in self.adapters.values():
            v.close()

    def mount(self, prefix, adapter):
        """
        Registers a connection adapter for URLs matching a given prefix, enabling custom handling of specific URL patterns.
        
        This allows fine-grained control over how requests are made to different parts of a domain or API, such as using different connection settings, authentication methods, or mock responses for testing. Adapters are automatically sorted by prefix length in descending order to ensure more specific (longer) prefixes take precedence over general ones when matching URLs.
        
        Args:
            prefix: The URL prefix (e.g., 'https://api.example.com/v1/') to which the adapter should be applied.
            adapter: The connection adapter instance that will handle requests matching the given prefix.
        """
        self.adapters[prefix] = adapter
        keys_to_move = [k for k in self.adapters if len(k) < len(prefix)]

        for key in keys_to_move:
            self.adapters[key] = self.adapters.pop(key)

    def __getstate__(self):
        """
        Returns the object's state as a dictionary for serialization via pickle.
        
        This method ensures that all attributes defined in `self.__attrs__` are properly captured during pickling, with missing attributes defaulting to None. It is essential for preserving the object's state across serialization and deserialization, which is particularly important in distributed systems or when caching HTTP sessions in Requests. This enables consistent behavior when restoring objects, such as session state or request configurations, after being saved.
        
        Returns:
            A dictionary mapping attribute names to their values, with missing attributes set to None
        """
        state = {attr: getattr(self, attr, None) for attr in self.__attrs__}
        return state

    def __setstate__(self, state):
        """
        Restores the object's state from a serialized dictionary, enabling persistence and reconstruction of request sessions or custom objects.
        
        Args:
            state: A dictionary containing attribute names as keys and their corresponding values to restore, used to reconstruct the object's internal state after deserialization.
        """
        for attr, value in state.items():
            setattr(self, attr, value)


def session():
    """
    Returns a reusable :class:`Session` object for managing HTTP connections and state across multiple requests.
    
    This function provides a convenient way to create a session that maintains cookies, authentication, and connection pooling across requests, which improves performance and simplifies stateful interactions with web services. It is particularly useful for scenarios involving repeated requests to the same host, such as API usage or web scraping, where persistent settings and session state are beneficial.
    
    Returns:
        A :class:`Session` object for context-management and stateful HTTP interactions.
    """
    return Session()
