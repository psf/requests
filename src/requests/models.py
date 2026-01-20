"""
requests.models
~~~~~~~~~~~~~~~

This module contains the primary objects that power Requests.
"""

import datetime

# Import encoding now, to avoid implicit import later.
# Implicit import within threads may cause LookupError when standard library is in a ZIP,
# such as in Embedded Python. See https://github.com/psf/requests/issues/3578.
import encodings.idna  # noqa: F401
from io import UnsupportedOperation

from urllib3.exceptions import (
    DecodeError,
    LocationParseError,
    ProtocolError,
    ReadTimeoutError,
    SSLError,
)
from urllib3.fields import RequestField
from urllib3.filepost import encode_multipart_formdata
from urllib3.util import parse_url

from ._internal_utils import to_native_string, unicode_is_ascii
from .auth import HTTPBasicAuth
from .compat import (
    Callable,
    JSONDecodeError,
    Mapping,
    basestring,
    builtin_str,
    chardet,
    cookielib,
)
from .compat import json as complexjson
from .compat import urlencode, urlsplit, urlunparse
from .cookies import _copy_cookie_jar, cookiejar_from_dict, get_cookie_header
from .exceptions import (
    ChunkedEncodingError,
    ConnectionError,
    ContentDecodingError,
    HTTPError,
    InvalidJSONError,
    InvalidURL,
)
from .exceptions import JSONDecodeError as RequestsJSONDecodeError
from .exceptions import MissingSchema
from .exceptions import SSLError as RequestsSSLError
from .exceptions import StreamConsumedError
from .hooks import default_hooks
from .status_codes import codes
from .structures import CaseInsensitiveDict
from .utils import (
    check_header_validity,
    get_auth_from_url,
    guess_filename,
    guess_json_utf,
    iter_slices,
    parse_header_links,
    requote_uri,
    stream_decode_response_unicode,
    super_len,
    to_key_val_list,
)

#: The set of HTTP status codes that indicate an automatically
#: processable redirect.
REDIRECT_STATI = (
    codes.moved,  # 301
    codes.found,  # 302
    codes.other,  # 303
    codes.temporary_redirect,  # 307
    codes.permanent_redirect,  # 308
)

DEFAULT_REDIRECT_LIMIT = 30
CONTENT_CHUNK_SIZE = 10 * 1024
ITER_CHUNK_SIZE = 512


class RequestEncodingMixin:
    """
    Mixin class to handle request encoding for HTTP requests.
    
        This class provides utility methods for encoding request parameters and files
        in various formats, such as URL-encoded form data and multipart/form-data.
    
        Methods:
        - path_url: Build the path URL to use.
        - _encode_params: Encode parameters in a piece of data.
        - _encode_files: Build the body for a multipart/form-data request.
    """

    @property
    def path_url(self):
        """
        Construct the full path URL by combining the path and query parameters from the original URL.
        
        This ensures consistent URL formatting when making HTTP requests, preserving the path and query string components for accurate endpoint identification. This is particularly important in the Requests library to maintain correct request targeting and avoid unintended behavior due to malformed or incomplete URLs.
        
        Returns:
            The reconstructed URL path with query parameters, if present
        """

        url = []

        p = urlsplit(self.url)

        path = p.path
        if not path:
            path = "/"

        url.append(path)

        query = p.query
        if query:
            url.append("?")
            url.append(query)

        return "".join(url)

    @staticmethod
    def _encode_params(data):
        """
        Encode request parameters into a URL-encoded format for HTTP requests.
        
        This function prepares query parameters or form data by encoding keys and values to UTF-8, ensuring proper transmission in HTTP requests. It supports dictionaries and lists of 2-tuples, preserving order when input is a list while handling arbitrary ordering for dictionaries. The result is a properly formatted string suitable for inclusion in URLs or POST bodies, which is essential for Requests' core functionality of sending well-formed HTTP requests with correct parameter encoding.
        
        Args:
            data: A dictionary, list of 2-tuples, string, or file-like object containing parameters to encode
        
        Returns:
            A URL-encoded string representing the parameters, or the original input if it's already a string or file-like object
        """

        if isinstance(data, (str, bytes)):
            return data
        elif hasattr(data, "read"):
            return data
        elif hasattr(data, "__iter__"):
            result = []
            for k, vs in to_key_val_list(data):
                if isinstance(vs, basestring) or not hasattr(vs, "__iter__"):
                    vs = [vs]
                for v in vs:
                    if v is not None:
                        result.append(
                            (
                                k.encode("utf-8") if isinstance(k, str) else k,
                                v.encode("utf-8") if isinstance(v, str) else v,
                            )
                        )
            return urlencode(result, doseq=True)
        else:
            return data

    @staticmethod
    def _encode_files(files, data):
        """
        Build the multipart/form-data request body from file fields and form data, enabling proper encoding of files and form parameters for HTTP requests.
        
        This function is essential for uploading files via HTTP POST requests, particularly when using the `requests` library's multipart encoding capabilities. It handles various file input formats—including dictionaries, lists of tuples, and file-like objects—and ensures correct MIME encoding with proper content types and headers.
        
        Args:
            files: A dictionary or list of tuples specifying file fields. Tuples can be 2-tuples (filename, fileobj), 3-tuples (filename, fileobj, content_type), or 4-tuples (filename, fileobj, content_type, custom_headers).
            data: A dictionary or list of tuples containing non-file form fields to include in the request.
        
        Returns:
            A tuple containing the encoded request body (bytes) and the corresponding Content-Type header value for multipart/form-data.
        """
        if not files:
            raise ValueError("Files must be provided.")
        elif isinstance(data, basestring):
            raise ValueError("Data must not be a string.")

        new_fields = []
        fields = to_key_val_list(data or {})
        files = to_key_val_list(files or {})

        for field, val in fields:
            if isinstance(val, basestring) or not hasattr(val, "__iter__"):
                val = [val]
            for v in val:
                if v is not None:
                    # Don't call str() on bytestrings: in Py3 it all goes wrong.
                    if not isinstance(v, bytes):
                        v = str(v)

                    new_fields.append(
                        (
                            field.decode("utf-8")
                            if isinstance(field, bytes)
                            else field,
                            v.encode("utf-8") if isinstance(v, str) else v,
                        )
                    )

        for k, v in files:
            # support for explicit filename
            ft = None
            fh = None
            if isinstance(v, (tuple, list)):
                if len(v) == 2:
                    fn, fp = v
                elif len(v) == 3:
                    fn, fp, ft = v
                else:
                    fn, fp, ft, fh = v
            else:
                fn = guess_filename(v) or k
                fp = v

            if isinstance(fp, (str, bytes, bytearray)):
                fdata = fp
            elif hasattr(fp, "read"):
                fdata = fp.read()
            elif fp is None:
                continue
            else:
                fdata = fp

            rf = RequestField(name=k, data=fdata, filename=fn, headers=fh)
            rf.make_multipart(content_type=ft)
            new_fields.append(rf)

        body, content_type = encode_multipart_formdata(new_fields)

        return body, content_type


class RequestHooksMixin:
    """
    Mixin class to provide request hook functionality for HTTP clients.
    
        This class enables the registration and management of hooks that can be executed
        before or after HTTP requests, allowing for customization of request behavior
        such as authentication, logging, or request transformation.
    
        Attributes:
        - _hooks: A dictionary storing registered hooks, where keys are hook types
          (e.g., 'request', 'response') and values are lists of callable functions.
    
        Methods:
        - register_hook: Register a hook function to be called during request processing.
        - deregister_hook: Remove a previously registered hook function.
        - _get_hooks: Retrieve the list of hooks for a given type.
        - _run_hooks: Execute all hooks of a given type with provided arguments.
    """

    def register_hook(self, event, hook):
        """
        Register a callback function to be executed when a specific event occurs during request processing.
        
        This allows users to extend Requests' behavior by injecting custom logic at key points in the HTTP request lifecycle, such as before sending a request or after receiving a response. Hooks are essential for implementing features like logging, monitoring, automatic retry mechanisms, or modifying request/response data dynamically.
        
        Args:
            event: The name of the event to register the hook for (e.g., 'pre_request', 'response').
            hook: A callable function or iterable of callables to execute when the event is triggered.
        """

        if event not in self.hooks:
            raise ValueError(f'Unsupported event specified, with event name "{event}"')

        if isinstance(hook, Callable):
            self.hooks[event].append(hook)
        elif hasattr(hook, "__iter__"):
            self.hooks[event].extend(h for h in hook if isinstance(h, Callable))

    def deregister_hook(self, event, hook):
        """
        Remove a previously registered hook for a specific event, allowing fine-grained control over request/response processing.
        
        Args:
            event: The event name (e.g., 'pre_request', 'response') for which the hook was registered.
            hook: The function to be removed from the hook list for the specified event.
        
        Returns:
            True if the hook was successfully removed (i.e., it existed), False if it was not found or already deregistered.
        
        This function enables dynamic modification of request lifecycle behavior—such as custom logging, authentication, or response transformation—by allowing hooks to be safely removed when no longer needed, maintaining clean and efficient execution flow in HTTP workflows.
        """

        try:
            self.hooks[event].remove(hook)
            return True
        except ValueError:
            return False


class Request(RequestHooksMixin):
    """
    A customizable HTTP request object used to define and manage HTTP operations with flexibility and ease.
    
        Used to prepare a :class:`PreparedRequest <PreparedRequest>`, which is sent to the server.
    
        :param method: HTTP method to use.
        :param url: URL to send.
        :param headers: dictionary of headers to send.
        :param files: dictionary of {filename: fileobject} files to multipart upload.
        :param data: the body to attach to the request. If a dictionary or
            list of tuples ``[(key, value)]`` is provided, form-encoding will
            take place.
        :param json: json for the body to attach to the request (if files or data is not specified).
        :param params: URL parameters to append to the URL. If a dictionary or
            list of tuples ``[(key, value)]`` is provided, form-encoding will
            take place.
        :param auth: Auth handler or (user, pass) tuple.
        :param cookies: dictionary or CookieJar of cookies to attach to this request.
        :param hooks: dictionary of callback hooks, for internal usage.
    
        Usage::
    
          >>> import requests
          >>> req = requests.Request('GET', 'https://httpbin.org/get')
          >>> req.prepare()
          <PreparedRequest [GET]>
    """


    def __init__(
        self,
        method=None,
        url=None,
        headers=None,
        files=None,
        data=None,
        params=None,
        auth=None,
        cookies=None,
        hooks=None,
        json=None,
    ):
        """
        Initialize a request object to encapsulate HTTP request parameters for easy execution via the Requests library.
        
        This constructor sets up the foundational components of an HTTP request—such as method, URL, headers, and payload—enabling consistent and reusable request configurations. By providing sensible defaults and handling parameter normalization, it supports the library's goal of simplifying HTTP interactions for developers, making it easier to send requests with minimal boilerplate code.
        
        Args:
            method: HTTP method to use (e.g., 'GET', 'POST') (default: None)
            url: URL to send the request to (default: None)
            headers: Dictionary of HTTP headers to include (default: empty dict)
            files: List of files to send in the request (default: empty list)
            data: Data to send in the request body (default: empty list)
            params: Dictionary of URL parameters to append to the URL (default: empty dict)
            auth: Authentication credentials (default: None)
            cookies: Dictionary of cookies to include in the request (default: None)
            hooks: Dictionary of event hooks to register (default: empty dict)
            json: JSON data to send in the request body (default: None)
        """
        # Default empty dicts for dict params.
        data = [] if data is None else data
        files = [] if files is None else files
        headers = {} if headers is None else headers
        params = {} if params is None else params
        hooks = {} if hooks is None else hooks

        self.hooks = default_hooks()
        for k, v in list(hooks.items()):
            self.register_hook(event=k, hook=v)

        self.method = method
        self.url = url
        self.headers = headers
        self.files = files
        self.data = data
        self.json = json
        self.params = params
        self.auth = auth
        self.cookies = cookies

    def __repr__(self):
        """
        Returns a concise, human-readable representation of the request object, displaying the HTTP method in angle brackets for easy identification during debugging or logging.
        
        Returns:
            A formatted string in the form <Request [METHOD]>, where METHOD is the request's method attribute, enabling quick visual confirmation of the request type in interactive sessions or error traces.
        """
        return f"<Request [{self.method}]>"

    def prepare(self):
        """
        Constructs a prepared HTTP request object that is fully serialized and ready for transmission, enabling efficient and consistent sending of HTTP requests.
        
        Returns:
            A fully prepared :class:`PreparedRequest <PreparedRequest>` object containing all request data in a format suitable for sending over the network.
        """
        p = PreparedRequest()
        p.prepare(
            method=self.method,
            url=self.url,
            headers=self.headers,
            files=self.files,
            data=self.data,
            json=self.json,
            params=self.params,
            auth=self.auth,
            cookies=self.cookies,
            hooks=self.hooks,
        )
        return p


class PreparedRequest(RequestEncodingMixin, RequestHooksMixin):
    """
    A mutable representation of an HTTP request that has been fully prepared for sending, including all necessary headers, body content, and encoding details to ensure accurate transmission to the server.
    
        Instances are generated from a :class:`Request <Request>` object, and
        should not be instantiated manually; doing so may produce undesirable
        effects.
    
        Usage::
    
          >>> import requests
          >>> req = requests.Request('GET', 'https://httpbin.org/get')
          >>> r = req.prepare()
          >>> r
          <PreparedRequest [GET]>
    
          >>> s = requests.Session()
          >>> s.send(r)
          <Response [200]>
    """


    def __init__(self):
        """
        Initialize a request object with default values for HTTP method, URL, headers, body, and hooks to support flexible and consistent HTTP request construction.
        
        This setup enables Requests to maintain a clean, predictable interface for building HTTP requests, allowing users to easily customize request parameters while ensuring internal consistency. The initial null values for method, URL, body, and cookies (to be populated later via `prepare_cookies`) provide flexibility during request preparation, while the empty `hooks` dictionary supports extensibility for event-driven behavior such as authentication or logging. This design aligns with Requests' goal of simplifying HTTP interactions by abstracting low-level details and offering a seamless, intuitive API.
        """
        #: HTTP verb to send to the server.
        self.method = None
        #: HTTP URL to send the request to.
        self.url = None
        #: dictionary of HTTP headers.
        self.headers = None
        # The `CookieJar` used to create the Cookie header will be stored here
        # after prepare_cookies is called
        self._cookies = None
        #: request body to send to the server.
        self.body = None
        #: dictionary of callback hooks, for internal usage.
        self.hooks = default_hooks()
        #: integer denoting starting position of a readable file-like body.
        self._body_position = None

    def prepare(
        self,
        method=None,
        url=None,
        headers=None,
        files=None,
        data=None,
        params=None,
        auth=None,
        cookies=None,
        hooks=None,
        json=None,
    ):
        """
        Prepares a complete HTTP request by assembling all components—method, URL, headers, cookies, body, authentication, and hooks—into a standardized format for sending.
        
        Args:
            method: The HTTP method (e.g., GET, POST) to use for the request.
            url: The target URL for the request, optionally including query parameters.
            headers: Custom HTTP headers to include in the request.
            files: Files to upload, typically used in multipart form data.
            data: Form data or raw body content to send in the request body.
            params: URL query parameters to append to the request URL.
            auth: Authentication credentials or handler for authenticating the request.
            cookies: Cookies to include in the request.
            hooks: Callbacks to execute at various stages of the request lifecycle.
            json: JSON data to serialize and send in the request body.
        """

        self.prepare_method(method)
        self.prepare_url(url, params)
        self.prepare_headers(headers)
        self.prepare_cookies(cookies)
        self.prepare_body(data, files, json)
        self.prepare_auth(auth, url)

        # Note that prepare_auth must be last to enable authentication schemes
        # such as OAuth to work on a fully prepared request.

        # This MUST go after prepare_auth. Authenticators could add a hook
        self.prepare_hooks(hooks)

    def __repr__(self):
        """
        Returns a concise, human-readable representation of the PreparedRequest instance, primarily showing the HTTP method for debugging and logging purposes.
        
        This representation helps developers quickly identify the request method during troubleshooting or when inspecting request objects in interactive environments, aligning with Requests' goal of making HTTP interactions intuitive and transparent.
        
        Returns:
            A formatted string in the form '<PreparedRequest [METHOD]>', where METHOD is the HTTP method of the request.
        """
        return f"<PreparedRequest [{self.method}]>"

    def copy(self):
        """
        Create a deep copy of the current request object to ensure independent data structures for safe modification.
        
        This is essential in Requests for maintaining state integrity when working with sessions, hooks, or multiple request variations—allowing developers to safely modify copied requests without affecting the original, which supports reliable and predictable HTTP operations in complex workflows.
        """
        p = PreparedRequest()
        p.method = self.method
        p.url = self.url
        p.headers = self.headers.copy() if self.headers is not None else None
        p._cookies = _copy_cookie_jar(self._cookies)
        p.body = self.body
        p.hooks = self.hooks
        p._body_position = self._body_position
        return p

    def prepare_method(self, method):
        """
        Normalizes the HTTP method to uppercase for consistent internal handling.
        
        Args:
            method: The HTTP method (e.g., 'GET', 'POST') to prepare. Ensures case-insensitive method specification is standardized to uppercase, which supports reliable comparison and processing within the request lifecycle.
        """
        self.method = method
        if self.method is not None:
            self.method = to_native_string(self.method.upper())

    @staticmethod
    def _get_idna_encoded_host(host):
        """
        Converts a host string to its IDNA-encoded form to ensure proper internationalized domain name handling in HTTP requests.
        
        Args:
            host: The host string to encode, which may contain non-ASCII characters such as those from non-Latin scripts
        
        Returns:
            The IDNA-encoded host string in UTF-8 format, enabling correct DNS resolution for internationalized domain names
        """
        import idna

        try:
            host = idna.encode(host, uts46=True).decode("utf-8")
        except idna.IDNAError:
            raise UnicodeError
        return host

    def prepare_url(self, url, params):
        """
        Prepares an HTTP URL by normalizing its components, handling Unicode domains, encoding parameters, and ensuring valid URL structure for reliable HTTP requests.
        
        Args:
            url: The URL string or bytes to prepare, which may include non-ASCII characters or require IDNA encoding.
            params: Optional query parameters to encode and append to the URL.
        
        Returns:
            The fully prepared and normalized HTTP URL string, ready for use in HTTP requests with proper encoding and validation.
        """
        #: Accept objects that have string representations.
        #: We're unable to blindly call unicode/str functions
        #: as this will include the bytestring indicator (b'')
        #: on python 3.x.
        #: https://github.com/psf/requests/pull/2238
        if isinstance(url, bytes):
            url = url.decode("utf8")
        else:
            url = str(url)

        # Remove leading whitespaces from url
        url = url.lstrip()

        # Don't do any URL preparation for non-HTTP schemes like `mailto`,
        # `data` etc to work around exceptions from `url_parse`, which
        # handles RFC 3986 only.
        if ":" in url and not url.lower().startswith("http"):
            self.url = url
            return

        # Support for unicode domain names and paths.
        try:
            scheme, auth, host, port, path, query, fragment = parse_url(url)
        except LocationParseError as e:
            raise InvalidURL(*e.args)

        if not scheme:
            raise MissingSchema(
                f"Invalid URL {url!r}: No scheme supplied. "
                f"Perhaps you meant https://{url}?"
            )

        if not host:
            raise InvalidURL(f"Invalid URL {url!r}: No host supplied")

        # In general, we want to try IDNA encoding the hostname if the string contains
        # non-ASCII characters. This allows users to automatically get the correct IDNA
        # behaviour. For strings containing only ASCII characters, we need to also verify
        # it doesn't start with a wildcard (*), before allowing the unencoded hostname.
        if not unicode_is_ascii(host):
            try:
                host = self._get_idna_encoded_host(host)
            except UnicodeError:
                raise InvalidURL("URL has an invalid label.")
        elif host.startswith(("*", ".")):
            raise InvalidURL("URL has an invalid label.")

        # Carefully reconstruct the network location
        netloc = auth or ""
        if netloc:
            netloc += "@"
        netloc += host
        if port:
            netloc += f":{port}"

        # Bare domains aren't valid URLs.
        if not path:
            path = "/"

        if isinstance(params, (str, bytes)):
            params = to_native_string(params)

        enc_params = self._encode_params(params)
        if enc_params:
            if query:
                query = f"{query}&{enc_params}"
            else:
                query = enc_params

        url = requote_uri(urlunparse([scheme, netloc, path, None, query, fragment]))
        self.url = url

    def prepare_headers(self, headers):
        """
        Prepares HTTP headers for use in requests, ensuring case-insensitive handling and validating header values for correctness.
        
        Args:
            headers: A dictionary of HTTP headers to prepare. Invalid header values will raise an exception.
        """

        self.headers = CaseInsensitiveDict()
        if headers:
            for header in headers.items():
                # Raise exception on invalid header value.
                check_header_validity(header)
                name, value = header
                self.headers[to_native_string(name)] = value

    def prepare_body(self, data, files, json=None):
        """
        Prepares the HTTP request body by handling various data types including JSON, form data, file uploads, and streaming bodies.
        
        Args:
            data: The request data, which can be a dictionary, string, file-like object, or iterator. Used for form encoding or as raw body content.
            files: A dictionary of file fields and file contents for multipart encoding. Only used when uploading files.
            json: A Python object to serialize as JSON. Used when sending JSON data in the request body.
        """

        # Check if file, fo, generator, iterator.
        # If not, run through normal process.

        # Nottin' on you.
        body = None
        content_type = None

        if not data and json is not None:
            # urllib3 requires a bytes-like body. Python 2's json.dumps
            # provides this natively, but Python 3 gives a Unicode string.
            content_type = "application/json"

            try:
                body = complexjson.dumps(json, allow_nan=False)
            except ValueError as ve:
                raise InvalidJSONError(ve, request=self)

            if not isinstance(body, bytes):
                body = body.encode("utf-8")

        is_stream = all(
            [
                hasattr(data, "__iter__"),
                not isinstance(data, (basestring, list, tuple, Mapping)),
            ]
        )

        if is_stream:
            try:
                length = super_len(data)
            except (TypeError, AttributeError, UnsupportedOperation):
                length = None

            body = data

            if getattr(body, "tell", None) is not None:
                # Record the current file position before reading.
                # This will allow us to rewind a file in the event
                # of a redirect.
                try:
                    self._body_position = body.tell()
                except OSError:
                    # This differentiates from None, allowing us to catch
                    # a failed `tell()` later when trying to rewind the body
                    self._body_position = object()

            if files:
                raise NotImplementedError(
                    "Streamed bodies and files are mutually exclusive."
                )

            if length:
                self.headers["Content-Length"] = builtin_str(length)
            else:
                self.headers["Transfer-Encoding"] = "chunked"
        else:
            # Multi-part file uploads.
            if files:
                (body, content_type) = self._encode_files(files, data)
            else:
                if data:
                    body = self._encode_params(data)
                    if isinstance(data, basestring) or hasattr(data, "read"):
                        content_type = None
                    else:
                        content_type = "application/x-www-form-urlencoded"

            self.prepare_content_length(body)

            # Add content-type if it wasn't explicitly provided.
            if content_type and ("content-type" not in self.headers):
                self.headers["Content-Type"] = content_type

        self.body = body

    def prepare_content_length(self, body):
        """
        Set the Content-Length header based on the request body and method to ensure proper HTTP protocol compliance.
        
        This function ensures that HTTP requests adhere to the expected format by setting the Content-Length header when a body is present, or explicitly setting it to 0 for methods that can have a body but don't. This is essential for reliable communication with servers, particularly when using chunked transfer encoding is not desired or supported. The logic prevents malformed requests and supports consistent behavior across different HTTP methods.
        
        Args:
            body: The request body data, which may be a string, bytes, or iterable. If provided, its length determines the Content-Length value.
        """
        if body is not None:
            length = super_len(body)
            if length:
                # If length exists, set it. Otherwise, we fallback
                # to Transfer-Encoding: chunked.
                self.headers["Content-Length"] = builtin_str(length)
        elif (
            self.method not in ("GET", "HEAD")
            and self.headers.get("Content-Length") is None
        ):
            # Set Content-Length to 0 for methods that can have a body
            # but don't provide one. (i.e. not GET or HEAD)
            self.headers["Content-Length"] = "0"

    def prepare_auth(self, auth, url=""):
        """
        Prepares HTTP authentication data for the request, extracting credentials from the URL if none are explicitly provided. This ensures secure and consistent authentication handling across requests, aligning with Requests' goal of simplifying HTTP interactions while supporting robust authentication workflows.
        
        Args:
            auth: Authentication credentials (e.g., tuple for basic auth, or an Auth object), or None to extract from URL.
            url: Optional URL to extract auth information from if auth is not provided.
        """

        # If no Auth is explicitly provided, extract it from the URL first.
        if auth is None:
            url_auth = get_auth_from_url(self.url)
            auth = url_auth if any(url_auth) else None

        if auth:
            if isinstance(auth, tuple) and len(auth) == 2:
                # special-case basic HTTP auth
                auth = HTTPBasicAuth(*auth)

            # Allow auth to make its changes.
            r = auth(self)

            # Update self to reflect the auth changes.
            self.__dict__.update(r.__dict__)

            # Recompute Content-Length
            self.prepare_content_length(self.body)

    def prepare_cookies(self, cookies):
        """
        Prepares HTTP cookie data for inclusion in the request headers.
        
        This function converts provided cookie data into a properly formatted Cookie header using cookielib, ensuring cookies are correctly serialized and included in outgoing requests. It is essential for maintaining session state and handling server-side cookies, which is a core capability of Requests for interacting with web services that rely on cookies for authentication and tracking.
        
        Args:
            cookies: A dictionary of cookie key-value pairs, or a cookielib.CookieJar object containing cookie data to be included in the request.
        """
        if isinstance(cookies, cookielib.CookieJar):
            self._cookies = cookies
        else:
            self._cookies = cookiejar_from_dict(cookies)

        cookie_header = get_cookie_header(self._cookies, self)
        if cookie_header is not None:
            self.headers["Cookie"] = cookie_header

    def prepare_hooks(self, hooks):
        """
        Prepares and registers event hooks for HTTP request lifecycle events, enabling custom behavior during request processing.
        
        Args:
            hooks: A dictionary mapping event names to callback functions. If None or falsy, an empty list is used to avoid iteration errors.
        """
        # hooks can be passed as None to the prepare method and to this
        # method. To prevent iterating over None, simply use an empty list
        # if hooks is False-y
        hooks = hooks or []
        for event in hooks:
            self.register_hook(event, hooks[event])


class Response:
    """
    The :class:`Response <Response>` object, which contains a
        server's response to an HTTP request.
    """


    __attrs__ = [
        "_content",
        "status_code",
        "headers",
        "url",
        "history",
        "encoding",
        "reason",
        "cookies",
        "elapsed",
        "request",
    ]

    def __init__(self):
        """
        Initialize a Response object with default values for HTTP response attributes.
        
        This constructor sets up the foundational state for an HTTP response within the Requests library, enabling consistent handling of response data across all HTTP operations. By initializing key attributes like status code, headers, cookies, and timing information to safe defaults, it ensures reliable behavior during request processing, redirect handling, and content retrieval—supporting Requests' core purpose of providing a simple, intuitive interface for HTTP interactions while maintaining internal consistency and extensibility. The response object serves as the primary container for all data returned from a server, allowing users to access content, headers, status, and metadata in a structured, predictable way.
        """
        self._content = False
        self._content_consumed = False
        self._next = None

        #: Integer Code of responded HTTP Status, e.g. 404 or 200.
        self.status_code = None

        #: Case-insensitive Dictionary of Response Headers.
        #: For example, ``headers['content-encoding']`` will return the
        #: value of a ``'Content-Encoding'`` response header.
        self.headers = CaseInsensitiveDict()

        #: File-like object representation of response (for advanced usage).
        #: Use of ``raw`` requires that ``stream=True`` be set on the request.
        #: This requirement does not apply for use internally to Requests.
        self.raw = None

        #: Final URL location of Response.
        self.url = None

        #: Encoding to decode with when accessing r.text.
        self.encoding = None

        #: A list of :class:`Response <Response>` objects from
        #: the history of the Request. Any redirect responses will end
        #: up here. The list is sorted from the oldest to the most recent request.
        self.history = []

        #: Textual reason of responded HTTP Status, e.g. "Not Found" or "OK".
        self.reason = None

        #: A CookieJar of Cookies the server sent back.
        self.cookies = cookiejar_from_dict({})

        #: The amount of time elapsed between sending the request
        #: and the arrival of the response (as a timedelta).
        #: This property specifically measures the time taken between sending
        #: the first byte of the request and finishing parsing the headers. It
        #: is therefore unaffected by consuming the response content or the
        #: value of the ``stream`` keyword argument.
        self.elapsed = datetime.timedelta(0)

        #: The :class:`PreparedRequest <PreparedRequest>` object to which this
        #: is a response.
        self.request = None

    def __enter__(self):
        """
        Enter the runtime context for this object, enabling it to be used in a 'with' statement.
        
        This allows the request session to be managed automatically, ensuring proper setup and cleanup of resources such as connections and cookies. The instance itself is returned to support fluent usage in context managers.
        
        Returns:
            The instance itself, enabling use in 'with' statements.
        """
        return self

    def __exit__(self, *args):
        """
        Closes the underlying connection and releases associated resources when exiting a context block.
        
        This ensures proper cleanup of network resources, preventing resource leaks and maintaining efficient connection handling across multiple requests. The context manager pattern is used to guarantee that connections are always closed, even if an exception occurs during request processing.
        
        Args:
            args: Exception information passed by the context manager protocol (type, value, traceback), if an exception occurred.
        """
        self.close()

    def __getstate__(self):
        """
        Returns a dictionary of instance attributes for pickling, ensuring all content is fully consumed before serialization to maintain data integrity.
        
        This is critical in Requests because response content may be lazily loaded from a stream. By consuming the content during pickling, we ensure that the serialized state reflects the complete, fully-read response body, preventing data loss or inconsistencies when the object is later unpickled.
        
        Returns:
            Dictionary mapping attribute names to their values, including all attributes listed in __attrs__ (default: None if attribute not present)
        """
        # Consume everything; accessing the content attribute makes
        # sure the content has been fully read.
        if not self._content_consumed:
            self.content

        return {attr: getattr(self, attr, None) for attr in self.__attrs__}

    def __setstate__(self, state):
        """
        Restores the object's state from a pickled representation, enabling persistent storage and reconstruction of request objects.
        
        Args:
            state: Dictionary containing the attributes to restore on the object, allowing the object to resume its previous state after serialization.
        """
        for name, value in state.items():
            setattr(self, name, value)

        # pickled objects do not have .raw
        setattr(self, "_content_consumed", True)
        setattr(self, "raw", None)

    def __repr__(self):
        """
        Returns a concise, human-readable representation of the response object, showing its HTTP status code. This helps developers quickly identify the outcome of an HTTP request during debugging or interactive use, aligning with Requests' goal of making HTTP interactions intuitive and transparent.
        
        Returns:
            A formatted string in the form <Response [status_code]>, where status_code is the HTTP status code of the response.
        """
        return f"<Response [{self.status_code}]>"

    def __bool__(self):
        """
        Returns True if the response status code indicates success (less than 400), enabling easy conditional checks for successful HTTP responses.
        
        This method supports the core purpose of Requests by providing a clean, intuitive way to determine if an HTTP request was successful without requiring explicit status code comparisons. It's commonly used in control flow to handle successful responses differently from client or server errors.
        
        Returns:
            bool: True if the status code is less than 400, indicating a successful response.
        """
        return self.ok

    def __nonzero__(self):
        """
        Returns True if the response status code indicates success (less than 400), which is useful for quickly determining whether an HTTP request was handled successfully by the server.
        
        This method supports the library's goal of simplifying HTTP interaction by providing a convenient way to check response success without manually comparing status codes. It's commonly used in conditional logic to handle successful responses differently from client or server errors.
        
        Returns:
            bool: True if status code is less than 400, False otherwise
        """
        return self.ok

    def __iter__(self):
        """
        Allows the response object to be iterated over, enabling efficient streaming of response content.
        
        This supports the library's goal of providing a simple, intuitive interface for handling HTTP responses, particularly for large payloads where loading the entire content into memory is impractical. By yielding chunks of data incrementally, it reduces memory usage and enables real-time processing.
        
        Returns:
            An iterator that yields chunks of response content, 128 bytes at a time.
        """
        return self.iter_content(128)

    @property
    def ok(self):
        """
        Returns True if the response status code indicates success (less than 400), False otherwise.
        
        This method is used to quickly determine whether an HTTP request was successful from the client's perspective, aligning with the library's goal of simplifying HTTP interaction. It checks for status codes in the 2xx range (successful) and 3xx range (redirects), which are generally considered acceptable outcomes. Unlike checking for a specific status like 200 OK, this method provides a broader success indicator suitable for general use in applications that need to handle various successful responses.
        
        Returns:
            bool: True if the status code is less than 400, False otherwise
        """
        try:
            self.raise_for_status()
        except HTTPError:
            return False
        return True

    @property
    def is_redirect(self):
        """
        Determines if the response represents a valid HTTP redirect that can be automatically handled by Requests' redirect resolution system.
        
        This is used internally by Session.resolve_redirects to determine whether a response should be followed automatically, ensuring consistent and predictable behavior when dealing with redirects in web requests. The check verifies both the presence of a Location header and that the status code is one of the standard redirect statuses.
        
        Returns:
            True if the response is a well-formed redirect that can be processed automatically, False otherwise
        """
        return "location" in self.headers and self.status_code in REDIRECT_STATI

    @property
    def is_permanent_redirect(self):
        """
        Checks if the response indicates a permanent redirect, which is important for handling URL changes correctly in web interactions.
        
        Returns:
            True if the response has a Location header and a status code indicating a permanent redirect (301 or 308), False otherwise.
        """
        return "location" in self.headers and self.status_code in (
            codes.moved_permanently,
            codes.permanent_redirect,
        )

    @property
    def next(self):
        """
        Returns the PreparedRequest for the next step in a redirect chain, allowing the request flow to continue seamlessly through redirects.
        
        This enables Requests to automatically handle HTTP redirects while maintaining the state and configuration of each request in the chain, which is essential for reliable web interactions and API consumption.
        Returns:
            PreparedRequest for the next request in the redirect chain, or None if no further redirects are available.
        """
        return self._next

    @property
    def apparent_encoding(self):
        """
        Determines the most likely encoding of the response content using either charset_normalizer or chardet, falling back to UTF-8 if no detection library is available.
        
        Returns:
            The detected encoding as a string, or 'utf-8' as a fallback when encoding detection is not possible.
        """
        if chardet is not None:
            return chardet.detect(self.content)["encoding"]
        else:
            # If no character detection library is available, we'll fall back
            # to a standard Python utf-8 str.
            return "utf-8"

    def iter_content(self, chunk_size=1, decode_unicode=False):
        """
        Iterates over the response content in chunks, enabling efficient handling of large responses without loading the entire body into memory at once.
        
        This is particularly important for streaming responses (when `stream=True`) to prevent excessive memory usage, aligning with Requests' goal of providing a high-level, memory-efficient HTTP client for web interactions.
        
        Args:
            chunk_size: The number of bytes to read at a time. If None, the behavior depends on the stream setting: with `stream=True`, data is read as it arrives in whatever size the chunks are received; with `stream=False`, the entire response is returned as a single chunk.
            decode_unicode: If True, the content is decoded using the best available encoding based on the response headers, ensuring proper handling of Unicode text.
        
        Returns:
            An iterator that yields chunks of the response content, optionally decoded if `decode_unicode` is True.
        """

        def generate():
            # Special case for urllib3.
            if hasattr(self.raw, "stream"):
                try:
                    yield from self.raw.stream(chunk_size, decode_content=True)
                except ProtocolError as e:
                    raise ChunkedEncodingError(e)
                except DecodeError as e:
                    raise ContentDecodingError(e)
                except ReadTimeoutError as e:
                    raise ConnectionError(e)
                except SSLError as e:
                    raise RequestsSSLError(e)
            else:
                # Standard file-like object.
                while True:
                    chunk = self.raw.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

            self._content_consumed = True

        if self._content_consumed and isinstance(self._content, bool):
            raise StreamConsumedError()
        elif chunk_size is not None and not isinstance(chunk_size, int):
            raise TypeError(
                f"chunk_size must be an int, it is instead a {type(chunk_size)}."
            )
        # simulate reading small chunks of the content
        reused_chunks = iter_slices(self._content, chunk_size)

        stream_chunks = generate()

        chunks = reused_chunks if self._content_consumed else stream_chunks

        if decode_unicode:
            chunks = stream_decode_response_unicode(chunks, self)

        return chunks

    def iter_lines(
        self, chunk_size=ITER_CHUNK_SIZE, decode_unicode=False, delimiter=None
    ):
        """
        Iterates over response data line by line, enabling efficient processing of large responses without loading the entire content into memory.
        
        This is particularly useful when streaming responses (stream=True), as it allows incremental processing of data, which is essential for handling large or continuous data streams—such as real-time APIs or large file downloads—without exhausting system memory.
        
        Args:
            chunk_size: The size of each chunk to read from the response stream.
            decode_unicode: If True, attempts to decode bytes into Unicode using the response's encoding.
            delimiter: Custom delimiter to split lines; if None, uses the default line break characters.
        """

        pending = None

        for chunk in self.iter_content(
            chunk_size=chunk_size, decode_unicode=decode_unicode
        ):
            if pending is not None:
                chunk = pending + chunk

            if delimiter:
                lines = chunk.split(delimiter)
            else:
                lines = chunk.splitlines()

            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None

            yield from lines

        if pending is not None:
            yield pending

    @property
    def content(self):
        """
        Returns the response body as bytes, lazily loading it on first access to optimize performance and memory usage.
        
        This allows users to efficiently retrieve raw response data without immediately consuming the entire content, which is especially useful for large responses or when only partial data is needed. The content is only read once and cached, ensuring subsequent accesses are fast and avoiding redundant network operations.
        
        Returns:
            The response body as bytes, or None if the response has no content or the status code indicates an error.
        """

        if self._content is False:
            # Read the contents.
            if self._content_consumed:
                raise RuntimeError("The content for this response was already consumed")

            if self.status_code == 0 or self.raw is None:
                self._content = None
            else:
                self._content = b"".join(self.iter_content(CONTENT_CHUNK_SIZE)) or b""

        self._content_consumed = True
        # don't need to release the connection; that's been handled by urllib3
        # since we exhausted the data.
        return self._content

    @property
    def text(self):
        """
        Returns the response content as a Unicode string, automatically detecting encoding from HTTP headers or using heuristics if none is specified.
        
        This method enables users to easily access textual content from HTTP responses in a consistent, human-readable format, which is essential for processing web data such as HTML, JSON, or plain text. If no encoding is provided in the response headers, Requests attempts to guess the correct encoding using `charset_normalizer` or `chardet`, ensuring accurate text representation even when servers don't specify encoding properly.
        
        Returns:
            The response body decoded into a Unicode string
        """

        # Try charset from content-type
        content = None
        encoding = self.encoding

        if not self.content:
            return ""

        # Fallback to auto-detected encoding.
        if self.encoding is None:
            encoding = self.apparent_encoding

        # Decode unicode from given encoding.
        try:
            content = str(self.content, encoding, errors="replace")
        except (LookupError, TypeError):
            # A LookupError is raised if the encoding was not found which could
            # indicate a misspelling or similar mistake.
            #
            # A TypeError can be raised if encoding is None
            #
            # So we try blindly encoding.
            content = str(self.content, errors="replace")

        return content

    def json(self, **kwargs):
        """
        Decodes the response body as a JSON object, providing a convenient way to work with API responses that return structured data.
        
        This method is essential for interacting with modern web APIs, which commonly return data in JSON format. It handles encoding detection automatically and falls back to text-based decoding if needed, ensuring robustness across different server implementations.
        
        Args:
            **kwargs: Additional arguments passed to json.loads for customizing parsing behavior
        
        Returns:
            A Python object (dict, list, str, etc.) representing the parsed JSON content
        """
        r"""Decodes the JSON response body (if any) as a Python object.

        This may return a dictionary, list, etc. depending on what is in the response.

        :param \*\*kwargs: Optional arguments that ``json.loads`` takes.
        :raises requests.exceptions.JSONDecodeError: If the response body does not
            contain valid json.
        """

        if not self.encoding and self.content and len(self.content) > 3:
            # No encoding set. JSON RFC 4627 section 3 states we should expect
            # UTF-8, -16 or -32. Detect which one to use; If the detection or
            # decoding fails, fall back to `self.text` (using charset_normalizer to make
            # a best guess).
            encoding = guess_json_utf(self.content)
            if encoding is not None:
                try:
                    return complexjson.loads(self.content.decode(encoding), **kwargs)
                except UnicodeDecodeError:
                    # Wrong UTF codec detected; usually because it's not UTF-8
                    # but some other 8-bit codec.  This is an RFC violation,
                    # and the server didn't bother to tell us what codec *was*
                    # used.
                    pass
                except JSONDecodeError as e:
                    raise RequestsJSONDecodeError(e.msg, e.doc, e.pos)

        try:
            return complexjson.loads(self.text, **kwargs)
        except JSONDecodeError as e:
            # Catch JSON-related errors and raise as requests.JSONDecodeError
            # This aliases json.JSONDecodeError and simplejson.JSONDecodeError
            raise RequestsJSONDecodeError(e.msg, e.doc, e.pos)

    @property
    def links(self):
        """
        Extracts and returns parsed link headers from the response, enabling easy navigation of related resources in API responses.
        
        Returns:
            A dictionary of parsed link headers, keyed by the 'rel' attribute or URL if 'rel' is missing, allowing developers to easily access and follow hypermedia links as defined in the HTTP Link header.
        """

        header = self.headers.get("link")

        resolved_links = {}

        if header:
            links = parse_header_links(header)

            for link in links:
                key = link.get("rel") or link.get("url")
                resolved_links[key] = link

        return resolved_links

    def raise_for_status(self):
        """
        Raises an HTTPError if the response status indicates an error (4xx or 5xx), providing a clear, descriptive message that includes the status code, reason, and URL. This function exists to help users quickly identify and handle HTTP errors during API interactions, aligning with Requests' goal of simplifying web requests by automatically detecting and signaling issues that require attention.
        """

        http_error_msg = ""
        if isinstance(self.reason, bytes):
            # We attempt to decode utf-8 first because some servers
            # choose to localize their reason strings. If the string
            # isn't utf-8, we fall back to iso-8859-1 for all other
            # encodings. (See PR #3538)
            try:
                reason = self.reason.decode("utf-8")
            except UnicodeDecodeError:
                reason = self.reason.decode("iso-8859-1")
        else:
            reason = self.reason

        if 400 <= self.status_code < 500:
            http_error_msg = (
                f"{self.status_code} Client Error: {reason} for url: {self.url}"
            )

        elif 500 <= self.status_code < 600:
            http_error_msg = (
                f"{self.status_code} Server Error: {reason} for url: {self.url}"
            )

        if http_error_msg:
            raise HTTPError(http_error_msg, response=self)

    def close(self):
        """
        Closes the underlying connection and returns it to the connection pool, ensuring resources are properly released.
        
        This method is crucial for efficient connection management in Requests, as it allows reuse of connections across multiple requests—improving performance by avoiding repeated TCP handshakes. While typically handled automatically by the library, explicit calling may be necessary in scenarios involving long-lived sessions or when managing resources manually.
        """
        if not self._content_consumed:
            self.raw.close()

        release_conn = getattr(self.raw, "release_conn", None)
        if release_conn is not None:
            release_conn()
