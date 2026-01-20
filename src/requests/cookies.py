"""
requests.cookies
~~~~~~~~~~~~~~~~

Compatibility code to be able to use `http.cookiejar.CookieJar` with requests.

requests.utils imports from here, so be careful with imports.
"""

import calendar
import copy
import time

from ._internal_utils import to_native_string
from .compat import Morsel, MutableMapping, cookielib, urlparse, urlunparse

try:
    import threading
except ImportError:
    import dummy_threading as threading


class MockRequest:
    """
    A wrapper around a `requests.Request` object that emulates the behavior of a traditional HTTP request, providing compatibility with existing code expecting a request-like interface while leveraging the modern features and simplicity of the Requests library.
    
        The code in `http.cookiejar.CookieJar` expects this interface in order to correctly
        manage cookie policies, i.e., determine whether a cookie can be set, given the
        domains of the request and the cookie.
    
        The original request object is read-only. The client is responsible for collecting
        the new headers via `get_new_headers()` and interpreting them appropriately. You
        probably want `get_cookie_header`, defined below.
    """


    def __init__(self, request):
        """
        Initializes the object with a request to extract and store the URL scheme for later use in HTTP operations.
        
        The URL scheme (e.g., 'http' or 'https') is crucial for determining the protocol used in subsequent requests, ensuring proper handling of secure vs. non-secure connections. This setup supports Requests' core purpose of simplifying HTTP interactions by abstracting low-level protocol details.
        
        Args:
            request: The request object containing the URL and other attributes used to initialize the instance.
        """
        self._r = request
        self._new_headers = {}
        self.type = urlparse(self._r.url).scheme

    def get_type(self):
        """
        Returns the type of the current instance, which helps identify the specific request or response type within the Requests library's object hierarchy. This is useful for type-based routing and handling in complex HTTP workflows.
        
        Returns:
            The type attribute of the instance
        """
        return self.type

    def get_host(self):
        """
        Extracts the host component from the URL to support consistent URL handling and network location identification across requests.
        
        This is essential for features like session management, cookie domain handling, and request routing, ensuring that HTTP operations are correctly scoped to the intended server. The host includes the port if specified, preserving the full network location.
        
        Returns:
            The host part of the URL, including port if specified
        """
        return urlparse(self._r.url).netloc

    def get_origin_req_host(self):
        """
        Returns the original host specified in the HTTP request, typically extracted from the Host header. This is essential for maintaining accurate request context in scenarios like redirects or proxy handling, ensuring the correct origin is preserved for security and routing purposes.
        
        Returns:
            The host value as specified in the request, typically derived from the Host header or equivalent source.
        """
        return self.get_host()

    def get_full_url(self):
        """
        Reconstructs the full URL of the response by respecting the Host header when present, ensuring the URL reflects the expected domain as specified by the server. This is crucial in scenarios like redirects or response handling where the original URL may not match the actual host the client should expect, maintaining consistency and correctness in HTTP interactions.
        
        Returns:
            The reconstructed full URL based on the response's URL and Host header (if set).
        """
        # Only return the response's URL if the user hadn't set the Host
        # header
        if not self._r.headers.get("Host"):
            return self._r.url
        # If they did set it, retrieve it and reconstruct the expected domain
        host = to_native_string(self._r.headers["Host"], encoding="utf-8")
        parsed = urlparse(self._r.url)
        # Reconstruct the URL as we expect it
        return urlunparse(
            [
                parsed.scheme,
                host,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ]
        )

    def is_unverifiable(self):
        """
        Indicates whether the current object's state or data cannot be verified, which is relevant for security-sensitive operations in HTTP requests.
        
        Returns:
            True if verification is not possible, meaning the object's integrity or authenticity cannot be confirmed, which may indicate a potential security risk or incomplete data in the context of request handling.
        """
        return True

    def has_header(self, name):
        """
        Checks whether a specific HTTP header is present in either the original response headers or any modified headers, enabling consistent header inspection during request/response processing.
        
        Args:
            name: The name of the header to check for, used to verify presence in the request or response metadata
        
        Returns:
            True if the header exists in either the original response headers or any modified headers, False otherwise
        """
        return name in self._r.headers or name in self._new_headers

    def get_header(self, name, default=None):
        """
        Retrieve a header value from the request or a fallback dictionary, prioritizing request headers while supporting custom defaults.
        
        Args:
            name: The name of the header to retrieve
            default: Value returned if the header is not found in either the request or fallback headers
        
        Returns:
            The header value if found, otherwise the default value
        """
        return self._r.headers.get(name, self._new_headers.get(name, default))

    def add_header(self, key, val):
        """
        Prevents accidental use of header addition on cookie jars; cookie management should be handled through dedicated methods.
        
        Args:
            key: The header name to add (unused, as this method is intentionally restricted).
            val: The header value to add (unused, as this method is intentionally restricted).
        """
        raise NotImplementedError(
            "Cookie headers should be added with add_unredirected_header()"
        )

    def add_unredirected_header(self, name, value):
        """
        Adds a header to the request that will persist across redirects, ensuring consistent behavior when following redirect responses.
        
        This is particularly useful in scenarios where you need to maintain specific headers (like authentication tokens or custom identifiers) throughout a chain of redirects, which is common in API interactions and web scraping workflows. By preserving these headers, Requests ensures reliable communication with endpoints that rely on header-based state or authorization.
        
        Args:
            name: The name of the header to add.
            value: The value to set for the header.
        """
        self._new_headers[name] = value

    def get_new_headers(self):
        """
        Returns the current set of custom headers that will be included in outgoing HTTP requests.
        
        This allows users to extend or modify the default headers sent by the request, enabling customization for specific API requirements or authentication needs. The returned dictionary is empty by default, indicating no custom headers have been set.
        
        Returns:
            A dictionary of custom headers to be applied to requests, or an empty dictionary if none have been specified.
        """
        return self._new_headers

    @property
    def unverifiable(self):
        """
        Determines if the current request state cannot be verified, which helps ensure security and reliability when interacting with web services.
        
        Returns:
            True if the state cannot be verified, False otherwise
        """
        return self.is_unverifiable()

    @property
    def origin_req_host(self):
        """
        Returns the host of the original request, which is essential for maintaining proper request context during redirects and authentication. This ensures that the request's origin is preserved, supporting accurate handling of HTTP redirects and authentication challenges in the Requests library.
        
        Returns:
            The host of the original request
        """
        return self.get_origin_req_host()

    @property
    def host(self):
        """
        Returns the current host value for the request, which is used to determine the base URL for HTTP operations. This is essential for maintaining consistent and correct request routing within the library's session and request lifecycle.
        
        Returns:
            The host value as determined by the get_host method
        """
        return self.get_host()


class MockResponse:
    """
    Represents a mock HTTP response object used for testing HTTP interactions, simulating the behavior of a real HTTP response with headers, status code, and response body. Designed to facilitate testing of HTTP client logic without requiring actual network requests.
    
        ...what? Basically, expose the parsed HTTP headers from the server response
        the way `http.cookiejar` expects to see them.
    """


    def __init__(self, headers):
        """
        Create a mock HTTP response object for use with cookiejar to simulate server responses during testing.
        
        Args:
            headers: A httplib.HTTPMessage or similar object containing the response headers
        """
        self._headers = headers

    def info(self):
        """
        Returns the headers associated with the request, allowing users to inspect or debug the HTTP headers being sent.
        
        Returns:
            The dictionary containing the headers, which may be empty if no headers have been set.
        """
        return self._headers

    def getheaders(self, name):
        """
        Return all values for the specified header name, supporting multiple values per header.
        
        This is essential for handling HTTP headers that can appear multiple times in a response (e.g., `Set-Cookie`), which is common in web protocols. Requests preserves all header values to ensure accurate data retrieval and proper handling of multi-valued headers, aligning with HTTP standards and enabling reliable interaction with web services.
        
        Args:
            name: The name of the header to retrieve values for.
        """
        self._headers.getheaders(name)


def extract_cookies_to_jar(jar, request, response):
    """
    Extract cookies from an HTTP response into a CookieJar to maintain session state across requests.
    
    This function enables Requests to properly handle and persist cookies received from servers, which is essential for maintaining authenticated sessions and tracking user state during web interactions. It bridges the gap between urllib3's low-level response objects and the higher-level cookie management provided by Python's `http.cookiejar`.
    
    Args:
        jar: A CookieJar instance to store extracted cookies (not necessarily a RequestsCookieJar)
        request: The original requests.Request object that initiated the request
        response: The urllib3.HTTPResponse object containing the server's response
    
    Returns:
        None. Cookies are extracted directly into the provided CookieJar.
    """
    if not (hasattr(response, "_original_response") and response._original_response):
        return
    # the _original_response field is the wrapped httplib.HTTPResponse object,
    req = MockRequest(request)
    # pull out the HTTPMessage with the headers and put it in the mock:
    res = MockResponse(response._original_response.msg)
    jar.extract_cookies(res, req)


def get_cookie_header(jar, request):
    """
    Generate a properly formatted Cookie header for an HTTP request based on stored cookies in the cookie jar.
    
    This function enables Requests to automatically include relevant cookies in outgoing requests, ensuring stateful interactions with web servers—such as maintaining login sessions or tracking user preferences—without requiring manual header management. It leverages the cookie jar's logic to determine which cookies apply to the given request, aligning with HTTP standards and enhancing the library's usability for real-world web interactions.
    
    Args:
        jar: The cookie jar containing stored cookies to be considered for the request.
        request: The request object (or equivalent) to which the cookie header should be applied.
    
    Returns:
        A formatted Cookie header string containing applicable cookies, or None if no cookies are relevant.
    """
    r = MockRequest(request)
    jar.add_cookie_header(r)
    return r.get_new_headers().get("Cookie")


def remove_cookie_by_name(cookiejar, name, domain=None, path=None):
    """
    Removes a cookie by name from the cookie jar, optionally filtering by domain and path.
    
    This function supports precise cookie management in HTTP sessions, which is essential for maintaining stateful interactions with web services. It enables users to clean up specific cookies—such as session tokens or authentication cookies—without affecting others, ensuring secure and predictable behavior in web scraping, API testing, and automated workflows.
    
    Args:
        cookiejar: The CookieJar instance from which to remove the cookie.
        name: The name of the cookie to remove.
        domain: Optional domain to restrict removal to; if not provided, removes matching cookies across all domains.
        path: Optional path to restrict removal to; if not provided, removes matching cookies across all paths.
    """
    clearables = []
    for cookie in cookiejar:
        if cookie.name != name:
            continue
        if domain is not None and domain != cookie.domain:
            continue
        if path is not None and path != cookie.path:
            continue
        clearables.append((cookie.domain, cookie.path, cookie.name))

    for domain, path, name in clearables:
        cookiejar.clear(domain, path, name)


class CookieConflictError(RuntimeError):
    """
    There are two cookies that meet the criteria specified in the cookie jar.
        Use .get and .set and include domain and path args in order to be more specific.
    """



class RequestsCookieJar(cookielib.CookieJar, MutableMapping):
    """
    A specialized cookie container that extends the functionality of http.cookiejar.CookieJar by providing a dictionary-like interface for easy access and manipulation of HTTP cookies during web requests.
    
        This is the CookieJar we create by default for requests and sessions that
        don't specify one, since some clients may expect response.cookies and
        session.cookies to support dict operations.
    
        Requests does not use the dict interface internally; it's just for
        compatibility with external client code. All requests code should work
        out of the box with externally provided instances of ``CookieJar``, e.g.
        ``LWPCookieJar`` and ``FileCookieJar``.
    
        Unlike a regular CookieJar, this class is pickleable.
    
        .. warning:: dictionary operations that are normally O(1) may be O(n).
    """


    def get(self, name, default=None, domain=None, path=None):
        """
        Retrieve a cookie value by name, optionally filtering by domain and path to handle naming conflicts when sharing a single cookie jar across multiple domains.
        
        This is particularly useful in scenarios where multiple domains use cookies with the same name, allowing the correct cookie to be retrieved based on the specific domain and path context. The operation is O(n) due to the need to search through all cookies, but this ensures accurate resolution of conflicts.
        
        Args:
            name: The name of the cookie to retrieve.
            default: Value to return if the cookie is not found.
            domain: Optional domain to narrow the search; used to resolve conflicts between cookies from different domains.
            path: Optional path to further narrow the search; ensures the correct cookie is selected based on its path scope.
        
        Returns:
            The cookie's value if found and matching the domain and path criteria; otherwise, the default value.
        """
        try:
            return self._find_no_duplicates(name, domain, path)
        except KeyError:
            return default

    def set(self, name, value, **kwargs):
        """
        Set a cookie in the jar with optional domain and path constraints to prevent naming collisions when managing cookies across multiple domains.
        
        Args:
            name: The name of the cookie to set.
            value: The value of the cookie. If None, the cookie is removed.
            **kwargs: Additional parameters such as domain, path, expires, secure, httponly, etc., to configure the cookie.
        
        Returns:
            The created Cookie object, or None if the cookie was removed.
        """
        # support client code that unsets cookies by assignment of a None value:
        if value is None:
            remove_cookie_by_name(
                self, name, domain=kwargs.get("domain"), path=kwargs.get("path")
            )
            return

        if isinstance(value, Morsel):
            c = morsel_to_cookie(value)
        else:
            c = create_cookie(name, value, **kwargs)
        self.set_cookie(c)
        return c

    def iterkeys(self):
        """
        Returns an iterator over the names of cookies stored in the cookie jar, enabling efficient iteration without loading all cookie data into memory.
        
        This supports the core purpose of Requests by providing a clean, memory-efficient way to inspect cookie names, which is particularly useful when debugging, validating session state, or implementing custom cookie handling logic in web interactions.
        """
        for cookie in iter(self):
            yield cookie.name

    def keys(self):
        """
        Returns a list of cookie names from the cookie jar, enabling easy access to all stored cookie keys.
        
        This is useful for inspecting or debugging the cookies managed by a session, particularly when tracking authentication tokens, session identifiers, or other stateful data stored in cookies. The returned list supports common dictionary-like operations, aligning with the expected behavior of dict.keys().
        
        Returns:
            A list of strings representing the names of cookies in the jar.
        """
        return list(self.iterkeys())

    def itervalues(self):
        """
        Returns an iterator over the values of cookies stored in the cookie jar, enabling efficient iteration without loading all values into memory at once.
        
        This supports the library's goal of providing a clean, intuitive interface for managing HTTP cookies during web interactions, allowing users to easily access cookie values in a memory-efficient manner when working with sessions or analyzing responses.
        """
        for cookie in iter(self):
            yield cookie.value

    def values(self):
        """
        Returns a list of cookie values from the session's cookie jar, enabling easy access to stored cookies for debugging or inspection.
        
        This is particularly useful in scenarios where you need to verify or analyze cookies set during HTTP interactions, such as during web scraping or API testing with Requests' session management. The function provides a convenient way to extract all cookie values in a format similar to Python dictionaries.
        
        Returns:
            A list of cookie values extracted from the cookie jar.
        """
        return list(self.itervalues())

    def iteritems(self):
        """
        Returns an iterator over (name, value) pairs from the cookie jar, enabling easy access to cookie data during HTTP requests.
        
        This method supports the common pattern of iterating through cookies in a dictionary-like manner, which is essential for maintaining state across requests in session-based interactions. It aligns with Requests' goal of providing a simple, intuitive interface for HTTP operations, including seamless cookie management for web scraping and API usage.
        """
        for cookie in iter(self):
            yield cookie.name, cookie.value

    def items(self):
        """
        Returns a list of (name, value) tuples representing the cookies stored in the jar, enabling seamless conversion to a standard Python dictionary. This allows users to easily inspect or serialize cookie data, supporting common patterns like `dict(RequestsCookieJar)` for interoperability with other code that expects plain dictionaries.
        
        Returns:
            A list of tuples containing cookie names and their corresponding values.
        """
        return list(self.iteritems())

    def list_domains(self):
        """
        Returns a list of unique domains from all cookies stored in the cookie jar.
        
        This helps track which domains have been interacted with during HTTP sessions, supporting features like domain-specific cookie management and ensuring proper cookie scope enforcement. Useful for debugging, session analysis, or implementing domain-based filtering in web scraping and API integration workflows.
        
        Returns:
            A list of unique domain strings present in the cookie jar.
        """
        domains = []
        for cookie in iter(self):
            if cookie.domain not in domains:
                domains.append(cookie.domain)
        return domains

    def list_paths(self):
        """
        Returns a list of unique path values from cookies stored in the jar, which is useful for tracking and managing cookie scopes in HTTP sessions.
        
        Returns:
            A list of unique path strings associated with cookies in the jar, enabling accurate handling of cookie domain and path restrictions during HTTP requests.
        """
        paths = []
        for cookie in iter(self):
            if cookie.path not in paths:
                paths.append(cookie.path)
        return paths

    def multiple_domains(self):
        """
        Checks whether the cookie jar contains cookies from multiple distinct domains, which helps determine if domain isolation is being maintained.
        
        This is useful for ensuring proper cookie management in sessions, particularly when handling cross-domain requests or validating session integrity. Returns True if multiple domains are present, False otherwise.
        """
        domains = []
        for cookie in iter(self):
            if cookie.domain is not None and cookie.domain in domains:
                return True
            domains.append(cookie.domain)
        return False  # there is only one domain in jar

    def get_dict(self, domain=None, path=None):
        """
        Returns a dictionary of cookie name-value pairs that match the optional domain and path filters.
        
        This is useful for inspecting or working with specific cookies stored in a session, such as when debugging authentication issues or extracting session data for reuse. The filtering by domain and path ensures only relevant cookies are included, aligning with HTTP cookie scoping rules.
        
        Args:
            domain: Optional domain to filter cookies by; if None, all domains are included.
            path: Optional path to filter cookies by; if None, all paths are included.
        
        Returns:
            A dictionary mapping cookie names to their values for cookies matching the specified domain and path.
        """
        dictionary = {}
        for cookie in iter(self):
            if (domain is None or cookie.domain == domain) and (
                path is None or cookie.path == path
            ):
                dictionary[cookie.name] = cookie.value
        return dictionary

    def __contains__(self, name):
        """
        Check if a cookie with the given name exists in the container, handling potential conflicts gracefully.
        
        This method supports Requests' goal of providing a robust and user-friendly HTTP client by ensuring reliable cookie lookup even when conflicting cookie definitions are present. It returns True if the cookie exists or if a conflict occurs during lookup, which helps maintain consistent behavior in session management and request handling.
        
        Args:
            name: The name of the cookie to check for existence
        
        Returns:
            True if the cookie exists or if a conflict occurred during lookup, False otherwise
        """
        try:
            return super().__contains__(name)
        except CookieConflictError:
            return True

    def __getitem__(self, name):
        """
        Retrieve a cookie by name for backward compatibility with dictionary-style access. This method is designed to support client code that expects dict-like behavior when accessing cookies, ensuring seamless integration with existing patterns.
        
        Since HTTP cookies can have multiple values with the same name, this method raises an exception if duplicates are found, encouraging developers to use the more explicit `get()` method when handling such cases. This design prioritizes clarity and safety over performance, aligning with Requests' goal of making HTTP interactions intuitive and predictable.
        
        Args:
            name: The name of the cookie to retrieve.
        
        Returns:
            The cookie value corresponding to the given name.
        """
        return self._find_no_duplicates(name)

    def __setitem__(self, name, value):
        """
        Dict-like assignment for cookie management, enabling intuitive syntax like `jar[name] = value`. This method maintains compatibility with dictionary-style usage while enforcing strict uniqueness of cookie names to prevent accidental overwrites, which aligns with Requests' goal of providing safe, predictable HTTP session handling. Use the explicit `set()` method when you need to replace an existing cookie.
        
        Args:
            name: The name of the cookie to set.
            value: The value to assign to the cookie.
        """
        self.set(name, value)

    def __delitem__(self, name):
        """
        Removes a cookie by name, enabling fine-grained control over session state in HTTP requests.
        
        Args:
            name: The name of the cookie to delete, allowing users to manage persistent cookies during a session.
        """
        remove_cookie_by_name(self, name)

    def set_cookie(self, cookie, *args, **kwargs):
        """
        Sets a cookie after sanitizing its value if it's a quoted string, ensuring proper cookie formatting for HTTP requests.
        
        This function is part of Requests' cookie management system, which handles the correct serialization and transmission of cookies in HTTP requests. The sanitization step removes escaped quotes (e.g., `\"`) from cookie values that are enclosed in double quotes, which is a common format in Set-Cookie headers. This ensures that cookies are sent correctly to servers without malformed values.
        
        Args:
            cookie: The cookie object to set. If the cookie's value is enclosed in double quotes, any escaped quotes within it are removed to maintain valid cookie syntax.
            *args: Additional arguments passed to the parent class's set_cookie method.
            **kwargs: Additional keyword arguments passed to the parent class's set_cookie method.
        
        Returns:
            The result of the parent class's set_cookie method call.
        """
        if (
            hasattr(cookie.value, "startswith")
            and cookie.value.startswith('"')
            and cookie.value.endswith('"')
        ):
            cookie.value = cookie.value.replace('\\"', "")
        return super().set_cookie(cookie, *args, **kwargs)

    def update(self, other):
        """
        Updates this cookie jar with cookies from another CookieJar or dict-like object, enabling seamless session state transfer between requests.
        
        Args:
            other: A CookieJar instance or dict-like object containing cookies to be added to this jar. This allows preserving and sharing authentication state, session data, or other cookies across different parts of an application or between multiple requests.
        """
        if isinstance(other, cookielib.CookieJar):
            for cookie in other:
                self.set_cookie(copy.copy(cookie))
        else:
            super().update(other)

    def _find(self, name, domain=None, path=None):
        """
        Retrieves the value of a cookie matching the specified name, domain, and path.
        
        This method is used internally by Requests to fetch cookie values during HTTP request processing. It helps maintain session state across requests by locating the appropriate cookie based on its name, domain, and path, which is essential for proper cookie handling in web interactions. When multiple cookies match the criteria, it returns the first one encountered, ensuring consistent behavior during request execution.
        
        Args:
            name: The name of the cookie to find.
            domain: The domain associated with the cookie (optional).
            path: The path associated with the cookie (optional).
        
        Returns:
            The value of the first matching cookie, or raises KeyError if no cookie matches the criteria.
        """
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        return cookie.value

        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def _find_no_duplicates(self, name, domain=None, path=None):
        """
        Finds a cookie value by name, domain, and path, ensuring no duplicate matches exist.
        
        This function is used internally by `__get_item__` and `get` to retrieve cookie values while enforcing uniqueness. It prevents ambiguity in cookie retrieval by raising an error if multiple cookies match the given criteria, which is critical for maintaining predictable behavior in HTTP session management. This ensures that cookie access in Requests remains reliable and consistent, especially when dealing with multiple cookies that share the same name but differ in domain or path.
        
        Args:
            name: The name of the cookie to find.
            domain: The domain of the cookie (optional).
            path: The path of the cookie (optional).
        
        Returns:
            The value of the cookie if exactly one match is found.
        
        Raises:
            KeyError: If no cookie matches the given criteria.
            CookieConflictError: If multiple cookies match the given criteria.
        """
        toReturn = None
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        if toReturn is not None:
                            # if there are multiple cookies that meet passed in criteria
                            raise CookieConflictError(
                                f"There are multiple cookies with name, {name!r}"
                            )
                        # we will eventually return this as long as no cookie conflict
                        toReturn = cookie.value

        if toReturn:
            return toReturn
        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def __getstate__(self):
        """
        Allows the instance to be pickled by removing the unpickleable RLock object.
        
        This is necessary because Requests uses persistent sessions with cookie jars that need to be serialized and restored, such as when saving session state to disk or transferring across processes. The function ensures that the cookie jar can be safely pickled while preserving all relevant state.
        
        Returns:
            A dictionary containing the instance's state without the RLock object.
        """
        state = self.__dict__.copy()
        # remove the unpickleable RLock object
        state.pop("_cookies_lock")
        return state

    def __setstate__(self, state):
        """
        Restores the state of the cookie jar after unpickling, ensuring thread safety.
        
        This method is necessary because the default `__setstate__` behavior does not initialize the lock used to protect concurrent access to cookies. Without this, multiple threads could modify the cookie store simultaneously, leading to race conditions. By re-creating the threading lock during unpickling, this class maintains its thread-safe behavior even after being serialized and deserialized, which is essential for reliable session management in multi-threaded applications.
        
        Args:
            state: The dictionary of attributes to restore from the pickled state.
        """
        self.__dict__.update(state)
        if "_cookies_lock" not in self.__dict__:
            self._cookies_lock = threading.RLock()

    def copy(self):
        """
        Return a deep copy of this RequestsCookieJar, ensuring independent cookie state.
        
        This allows safe manipulation of cookies in a new session without affecting the original jar, which is essential for maintaining isolated state across multiple requests or sessions in web interactions.
        
        Returns:
            A new RequestsCookieJar instance with identical cookies and policy settings
        """
        new_cj = RequestsCookieJar()
        new_cj.set_policy(self.get_policy())
        new_cj.update(self)
        return new_cj

    def get_policy(self):
        """
        Return the CookiePolicy instance used for managing cookie behavior in HTTP requests.
        
        This allows users to customize how cookies are handled during session-based interactions, ensuring consistent and secure cookie management across requests. The policy controls actions like accepting, rejecting, or filtering cookies based on domain, path, or other criteria.
        
        Returns:
            The CookiePolicy instance currently in use for handling cookie-related decisions.
        """
        return self._policy


def _copy_cookie_jar(jar):
    """
    Creates a deep copy of a cookie jar to ensure independent state management during HTTP sessions, which is essential for maintaining isolated cookie storage across multiple requests in the Requests library.
    
    Args:
        jar: The cookie jar to copy. If None, returns None. Supports both RequestsCookieJar and standard CookieJar types.
    """
    if jar is None:
        return None

    if hasattr(jar, "copy"):
        # We're dealing with an instance of RequestsCookieJar
        return jar.copy()
    # We're dealing with a generic CookieJar instance
    new_jar = copy.copy(jar)
    new_jar.clear()
    for cookie in jar:
        new_jar.set_cookie(copy.copy(cookie))
    return new_jar


def create_cookie(name, value, **kwargs):
    """
    Create a cookie with specified attributes for use in HTTP requests.
    
    This function constructs a cookie object that can be used to maintain state across HTTP requests, which is essential for session management, authentication, and tracking user sessions in web applications. By default, cookies are set for the root domain and sent with every request, enabling persistent state without requiring explicit domain or path configuration.
    
    Args:
        name: The name of the cookie.
        value: The value of the cookie.
        **kwargs: Optional parameters to customize the cookie, such as domain, path, secure, expires, and others.
    
    Returns:
        A `cookielib.Cookie` object configured with the provided parameters, ready to be used in a session or request.
    """
    result = {
        "version": 0,
        "name": name,
        "value": value,
        "port": None,
        "domain": "",
        "path": "/",
        "secure": False,
        "expires": None,
        "discard": True,
        "comment": None,
        "comment_url": None,
        "rest": {"HttpOnly": None},
        "rfc2109": False,
    }

    badargs = set(kwargs) - set(result)
    if badargs:
        raise TypeError(
            f"create_cookie() got unexpected keyword arguments: {list(badargs)}"
        )

    result.update(kwargs)
    result["port_specified"] = bool(result["port"])
    result["domain_specified"] = bool(result["domain"])
    result["domain_initial_dot"] = result["domain"].startswith(".")
    result["path_specified"] = bool(result["path"])

    return cookielib.Cookie(**result)


def morsel_to_cookie(morsel):
    """
    Convert a Morsel object to a Cookie object for use in HTTP requests, enabling proper cookie handling in sessions.
    
    This function is essential for Requests' cookie management system, allowing individual key-value pairs (represented as Morsel objects) to be converted into full Cookie objects that can be stored and sent with HTTP requests. This ensures compatibility with RFC 6265 cookie specifications and supports features like expiration, domain restrictions, and security flags.
    
    Args:
        morsel: A Morsel object containing a single key-value pair and associated cookie attributes
    
    Returns:
        A Cookie object configured with the attributes from the Morsel, ready to be used in HTTP requests
    """

    expires = None
    if morsel["max-age"]:
        try:
            expires = int(time.time() + int(morsel["max-age"]))
        except ValueError:
            raise TypeError(f"max-age: {morsel['max-age']} must be integer")
    elif morsel["expires"]:
        time_template = "%a, %d-%b-%Y %H:%M:%S GMT"
        expires = calendar.timegm(time.strptime(morsel["expires"], time_template))
    return create_cookie(
        comment=morsel["comment"],
        comment_url=bool(morsel["comment"]),
        discard=False,
        domain=morsel["domain"],
        expires=expires,
        name=morsel.key,
        path=morsel["path"],
        port=None,
        rest={"HttpOnly": morsel["httponly"]},
        rfc2109=False,
        secure=bool(morsel["secure"]),
        value=morsel.value,
        version=morsel["version"] or 0,
    )


def cookiejar_from_dict(cookie_dict, cookiejar=None, overwrite=True):
    """
    Converts a dictionary of cookie key-value pairs into a Requests CookieJar for use in HTTP sessions.
    
    This function enables seamless integration of cookie data from dictionaries into Requests' session management system, allowing developers to easily persist and send cookies across requests. It's particularly useful when restoring cookies from storage, handling authentication tokens, or pre-populating sessions with known cookie values.
    
    Args:
        cookie_dict: Dictionary of cookie names and values to add to the CookieJar.
        cookiejar: Optional existing CookieJar to populate; if None, a new RequestsCookieJar is created.
        overwrite: If True, replaces existing cookies with the same name; if False, preserves existing cookies.
    
    Returns:
        A CookieJar populated with the provided key-value pairs, ready for use in HTTP requests.
    """
    if cookiejar is None:
        cookiejar = RequestsCookieJar()

    if cookie_dict is not None:
        names_from_jar = [cookie.name for cookie in cookiejar]
        for name in cookie_dict:
            if overwrite or (name not in names_from_jar):
                cookiejar.set_cookie(create_cookie(name, cookie_dict[name]))

    return cookiejar


def merge_cookies(cookiejar, cookies):
    """
    Merge cookies from a dictionary or another CookieJar into the target CookieJar, ensuring consistent session state across requests.
    
    This function is essential for maintaining persistent cookies across HTTP sessions in Requests, allowing users to seamlessly carry over authentication tokens, session identifiers, and other stateful data between requests. It supports both dictionary-style cookie inputs and existing CookieJar objects, making it flexible for various use cases such as session reuse, web scraping, and API interactions.
    
    Args:
        cookiejar: The target CookieJar to which cookies will be added.
        cookies: A dictionary of cookies or a CookieJar object to merge into the target.
    
    Returns:
        The updated CookieJar with merged cookies, enabling consistent state management in HTTP sessions.
    """
    if not isinstance(cookiejar, cookielib.CookieJar):
        raise ValueError("You can only merge into CookieJar")

    if isinstance(cookies, dict):
        cookiejar = cookiejar_from_dict(cookies, cookiejar=cookiejar, overwrite=False)
    elif isinstance(cookies, cookielib.CookieJar):
        try:
            cookiejar.update(cookies)
        except AttributeError:
            for cookie_in_jar in cookies:
                cookiejar.set_cookie(cookie_in_jar)

    return cookiejar
