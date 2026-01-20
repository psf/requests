"""
requests.adapters
~~~~~~~~~~~~~~~~~

This module contains the transport adapters that Requests uses to define
and maintain connections.
"""

import os.path
import socket  # noqa: F401
import typing
import warnings

from urllib3.exceptions import ClosedPoolError, ConnectTimeoutError
from urllib3.exceptions import HTTPError as _HTTPError
from urllib3.exceptions import InvalidHeader as _InvalidHeader
from urllib3.exceptions import (
    LocationValueError,
    MaxRetryError,
    NewConnectionError,
    ProtocolError,
)
from urllib3.exceptions import ProxyError as _ProxyError
from urllib3.exceptions import ReadTimeoutError, ResponseError
from urllib3.exceptions import SSLError as _SSLError
from urllib3.poolmanager import PoolManager, proxy_from_url
from urllib3.util import Timeout as TimeoutSauce
from urllib3.util import parse_url
from urllib3.util.retry import Retry

from .auth import _basic_auth_str
from .compat import basestring, urlparse
from .cookies import extract_cookies_to_jar
from .exceptions import (
    ConnectionError,
    ConnectTimeout,
    InvalidHeader,
    InvalidProxyURL,
    InvalidSchema,
    InvalidURL,
    ProxyError,
    ReadTimeout,
    RetryError,
    SSLError,
)
from .models import Response
from .structures import CaseInsensitiveDict
from .utils import (
    DEFAULT_CA_BUNDLE_PATH,
    extract_zipped_paths,
    get_auth_from_url,
    get_encoding_from_headers,
    prepend_scheme_if_needed,
    select_proxy,
    urldefragauth,
)

try:
    from urllib3.contrib.socks import SOCKSProxyManager
except ImportError:

    def SOCKSProxyManager(*args, **kwargs):
        raise InvalidSchema("Missing dependencies for SOCKS support.")


if typing.TYPE_CHECKING:
    from .models import PreparedRequest


DEFAULT_POOLBLOCK = False
DEFAULT_POOLSIZE = 10
DEFAULT_RETRIES = 0
DEFAULT_POOL_TIMEOUT = None


def _urllib3_request_context(
    request: "PreparedRequest",
    verify: "bool | str | None",
    client_cert: "typing.Tuple[str, str] | str | None",
    poolmanager: "PoolManager",
) -> "(typing.Dict[str, typing.Any], typing.Dict[str, typing.Any])":
    """
    Constructs the necessary configuration for urllib3's connection pool and request parameters based on the request URL and security settings. This function enables Requests to securely and efficiently manage HTTP connections by translating high-level request and security options into low-level urllib3-compatible configurations, ensuring proper SSL verification and client certificate handling.
    
    Args:
        request: The PreparedRequest object containing the URL and other request details
        verify: Whether to verify SSL certificates (default: True), or a path to a CA bundle or directory
        client_cert: Path to client certificate file, or a tuple of (cert_file, key_file) for client authentication
        poolmanager: The PoolManager instance used to manage connection pools
    
    Returns:
        A tuple containing two dictionaries:
        - host_params: Configuration for the target host (scheme, host, port)
        - pool_kwargs: Configuration for the connection pool (cert requirements, CA paths, client cert info)
    """
    host_params = {}
    pool_kwargs = {}
    parsed_request_url = urlparse(request.url)
    scheme = parsed_request_url.scheme.lower()
    port = parsed_request_url.port

    cert_reqs = "CERT_REQUIRED"
    if verify is False:
        cert_reqs = "CERT_NONE"
    elif isinstance(verify, str):
        if not os.path.isdir(verify):
            pool_kwargs["ca_certs"] = verify
        else:
            pool_kwargs["ca_cert_dir"] = verify
    pool_kwargs["cert_reqs"] = cert_reqs
    if client_cert is not None:
        if isinstance(client_cert, tuple) and len(client_cert) == 2:
            pool_kwargs["cert_file"] = client_cert[0]
            pool_kwargs["key_file"] = client_cert[1]
        else:
            # According to our docs, we allow users to specify just the client
            # cert path
            pool_kwargs["cert_file"] = client_cert
    host_params = {
        "scheme": scheme,
        "host": parsed_request_url.hostname,
        "port": port,
    }
    return host_params, pool_kwargs


class BaseAdapter:
    """
    The Base Transport Adapter
    """


    def __init__(self):
        """
        Initialize the instance by delegating setup to the parent class.
        
        This method ensures proper initialization of base functionality required for HTTP request handling, such as session management and default configuration, enabling consistent behavior across request operations within the Requests library.
        """
        super().__init__()

    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None
    ):
        """
        Sends an HTTP request using the provided PreparedRequest object, enabling seamless interaction with web services by abstracting low-level networking details.
        
        Args:
            request: The PreparedRequest object containing the HTTP request configuration, including headers, data, and URL.
            stream: Whether to stream the response content, useful for large downloads or real-time processing.
            timeout: How long to wait for a response before timing out, either as a float (total time) or a tuple (connect, read timeouts).
            verify: Controls TLS certificate verification; set to True to validate certificates, False to skip verification, or provide a path to a custom CA bundle.
            cert: Optional SSL certificate to use for client authentication.
            proxies: Dictionary mapping protocol schemes to proxy URLs, allowing requests to be routed through intermediaries.
        """
        raise NotImplementedError

    def close(self):
        """
        Cleans up resources and state specific to the adapter, ensuring proper release of connections and system resources.
        
        This method is essential for maintaining efficient resource management in Requests' connection pooling and session handling. By properly closing adapter-specific components, it prevents resource leaks and ensures reliable operation during repeated HTTP interactions.
        """
        raise NotImplementedError


class HTTPAdapter(BaseAdapter):
    """
    An HTTP adapter that integrates with urllib3 to handle HTTP and HTTPS requests with automatic connection pooling, persistent sessions, and efficient resource management. It provides a seamless interface for sending requests while managing underlying transport details such as retries, timeouts, and connection reuse.
    
        Provides a general-case interface for Requests sessions to contact HTTP and
        HTTPS urls by implementing the Transport Adapter interface. This class will
        usually be created by the :class:`Session <Session>` class under the
        covers.
    
        :param pool_connections: The number of urllib3 connection pools to cache.
        :param pool_maxsize: The maximum number of connections to save in the pool.
        :param max_retries: The maximum number of retries each connection
            should attempt. Note, this applies only to failed DNS lookups, socket
            connections and connection timeouts, never to requests where data has
            made it to the server. By default, Requests does not retry failed
            connections. If you need granular control over the conditions under
            which we retry a request, import urllib3's ``Retry`` class and pass
            that instead.
        :param pool_block: Whether the connection pool should block for connections.
    
        Usage::
    
          >>> import requests
          >>> s = requests.Session()
          >>> a = requests.adapters.HTTPAdapter(max_retries=3)
          >>> s.mount('http://', a)
    """


    __attrs__ = [
        "max_retries",
        "config",
        "_pool_connections",
        "_pool_maxsize",
        "_pool_block",
    ]

    def __init__(
        self,
        pool_connections=DEFAULT_POOLSIZE,
        pool_maxsize=DEFAULT_POOLSIZE,
        max_retries=DEFAULT_RETRIES,
        pool_block=DEFAULT_POOLBLOCK,
    ):
        """
        Initialize the connection pool manager to efficiently manage HTTP connections and retry logic, enabling reliable and performant communication with web services.
        
        Args:
            pool_connections: The number of connection pools to cache, controlling the maximum concurrent connections to different hosts (default: DEFAULT_POOLSIZE).
            pool_maxsize: The maximum number of connections allowed per pool, limiting resource usage and preventing excessive connection creation (default: DEFAULT_POOLSIZE).
            max_retries: The maximum number of retry attempts for failed requests; when set to the default, retries are disabled for read operations to avoid unintended behavior (default: DEFAULT_RETRIES).
            pool_block: Whether to block when all connections in a pool are in use, ensuring orderly access to limited connection resources (default: DEFAULT_POOLBLOCK).
        """
        if max_retries == DEFAULT_RETRIES:
            self.max_retries = Retry(0, read=False)
        else:
            self.max_retries = Retry.from_int(max_retries)
        self.config = {}
        self.proxy_manager = {}

        super().__init__()

        self._pool_connections = pool_connections
        self._pool_maxsize = pool_maxsize
        self._pool_block = pool_block

        self.init_poolmanager(pool_connections, pool_maxsize, block=pool_block)

    def __getstate__(self):
        """
        Returns a dictionary of instance attributes for pickling, ensuring consistent serialization of request state.
        
        This enables safe persistence and reconstruction of request objects, such as when using sessions or caching requests across processes. The dictionary includes all attributes listed in `self.__attrs__`, with their current values, defaulting to None for missing attributes.
        
        Returns:
            Dictionary mapping attribute names to their values, or None if not present
        """
        return {attr: getattr(self, attr, None) for attr in self.__attrs__}

    def __setstate__(self, state):
        """
        Restores the object's state after unpickling, ensuring the connection pool and proxy configuration are properly reinitialized.
        
        Args:
            state: Dictionary containing the state to restore, including attributes like pool connections, maximum pool size, and blocking behavior, which are essential for maintaining consistent HTTP session behavior across pickled and restored instances.
        """
        # Can't handle by adding 'proxy_manager' to self.__attrs__ because
        # self.poolmanager uses a lambda function, which isn't pickleable.
        self.proxy_manager = {}
        self.config = {}

        for attr, value in state.items():
            setattr(self, attr, value)

        self.init_poolmanager(
            self._pool_connections, self._pool_maxsize, block=self._pool_block
        )

    def init_poolmanager(
        self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs
    ):
        """
        Initializes a connection pool manager for efficient HTTP connection reuse, enabling Requests to handle multiple concurrent requests with optimal performance and resource management.
        
        Args:
            connections: The number of connection pools to maintain, controlling how many different hosts can be connected to simultaneously.
            maxsize: The maximum number of connections allowed in each pool, limiting memory usage and preventing excessive resource consumption.
            block: Whether to wait (block) for a free connection when all connections in the pool are in use, ensuring reliable request handling under load.
            pool_kwargs: Additional arguments passed to urllib3's PoolManager to customize connection behavior, such as timeout settings or SSL configurations.
        """
        # save these values for pickling
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block

        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        """
        Return a configured urllib3 ProxyManager for the given proxy URL, enabling efficient connection pooling and proxy handling within Requests' HTTP adapter system.
        
        This function is used internally by Requests to manage proxy connections, ensuring that HTTP requests through proxies are handled efficiently with proper connection reuse and authentication support. It supports both HTTP and SOCKS proxies, automatically extracting credentials from the proxy URL when needed, and integrates with Requests' connection pooling to maintain performance and resource efficiency.
        
        Args:
            proxy: The proxy URL to configure the ProxyManager for, including optional authentication credentials.
            proxy_kwargs: Additional arguments to pass to the underlying ProxyManager constructor for customizing behavior.
        
        Returns:
            A configured ProxyManager instance ready to handle HTTP requests through the specified proxy.
        """
        if proxy in self.proxy_manager:
            manager = self.proxy_manager[proxy]
        elif proxy.lower().startswith("socks"):
            username, password = get_auth_from_url(proxy)
            manager = self.proxy_manager[proxy] = SOCKSProxyManager(
                proxy,
                username=username,
                password=password,
                num_pools=self._pool_connections,
                maxsize=self._pool_maxsize,
                block=self._pool_block,
                **proxy_kwargs,
            )
        else:
            proxy_headers = self.proxy_headers(proxy)
            manager = self.proxy_manager[proxy] = proxy_from_url(
                proxy,
                proxy_headers=proxy_headers,
                num_pools=self._pool_connections,
                maxsize=self._pool_maxsize,
                block=self._pool_block,
                **proxy_kwargs,
            )

        return manager

    def cert_verify(self, conn, url, verify, cert):
        """
        Verify SSL certificates for HTTPS connections, ensuring secure communication with remote servers. This method is part of Requests' internal mechanism to enforce TLS security when making HTTPS requests, and is exposed for advanced use cases like custom HTTP adapter implementations.
        
        Args:
            conn: The urllib3 connection object associated with the cert.
            url: The requested URL.
            verify: Controls whether to verify the server's TLS certificate; if True, uses the default CA bundle; if a string, uses the specified path to a CA bundle.
            cert: The SSL certificate to verify, either as a file path or a tuple of (cert_file, key_file).
        """
        if url.lower().startswith("https") and verify:
            cert_loc = None

            # Allow self-specified cert location.
            if verify is not True:
                cert_loc = verify

            if not cert_loc:
                cert_loc = extract_zipped_paths(DEFAULT_CA_BUNDLE_PATH)

            if not cert_loc or not os.path.exists(cert_loc):
                raise OSError(
                    f"Could not find a suitable TLS CA certificate bundle, "
                    f"invalid path: {cert_loc}"
                )

            conn.cert_reqs = "CERT_REQUIRED"

            if not os.path.isdir(cert_loc):
                conn.ca_certs = cert_loc
            else:
                conn.ca_cert_dir = cert_loc
        else:
            conn.cert_reqs = "CERT_NONE"
            conn.ca_certs = None
            conn.ca_cert_dir = None

        if cert:
            if not isinstance(cert, basestring):
                conn.cert_file = cert[0]
                conn.key_file = cert[1]
            else:
                conn.cert_file = cert
                conn.key_file = None
            if conn.cert_file and not os.path.exists(conn.cert_file):
                raise OSError(
                    f"Could not find the TLS certificate file, "
                    f"invalid path: {conn.cert_file}"
                )
            if conn.key_file and not os.path.exists(conn.key_file):
                raise OSError(
                    f"Could not find the TLS key file, invalid path: {conn.key_file}"
                )

    def build_response(self, req, resp):
        """
        Builds a requests.Response object from an urllib3 response to integrate low-level HTTP responses into Requests' high-level API. This allows the HTTPAdapter to properly handle server responses while maintaining consistency with Requests' abstractions like case-insensitive headers, automatic encoding detection, and cookie management.
        
        Args:
            req: The PreparedRequest used to generate the response, providing context such as URL and headers.
            resp: The urllib3 response object containing raw HTTP data from the server.
        
        Returns:
            A fully populated Response object that mirrors the server's response, including status code, headers, body, cookies, and request context, enabling seamless integration with Requests' higher-level features.
        """
        response = Response()

        # Fallback to None if there's no status_code, for whatever reason.
        response.status_code = getattr(resp, "status", None)

        # Make headers case-insensitive.
        response.headers = CaseInsensitiveDict(getattr(resp, "headers", {}))

        # Set encoding.
        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = resp
        response.reason = response.raw.reason

        if isinstance(req.url, bytes):
            response.url = req.url.decode("utf-8")
        else:
            response.url = req.url

        # Add new cookies from the server.
        extract_cookies_to_jar(response.cookies, req, resp)

        # Give the Response some context.
        response.request = req
        response.connection = self

        return response

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        """
        Build the connection pool key attributes used by urllib3 to select or reuse an existing connection, ensuring efficient and secure HTTP communication.
        
        This function determines the appropriate host and SSL-related parameters for a connection pool key based on the request, verification settings, and client certificate configuration. It enables Requests to maintain connection reuse across identical requests while respecting security settings like certificate verification and mutual TLS authentication.
        
        Args:
            request: The PreparedRequest being sent over the connection, containing information about the target host, scheme, and port.
            verify: Controls TLS certificate verification; can be a boolean to enable/disable verification or a string path to a custom CA bundle.
            cert: Optional SSL certificate for client authentication (mTLS), specified as a file path or a tuple of certificate and key file paths.
        
        Returns:
            A tuple of two dictionaries: the first contains host parameters (scheme, hostname, port) for pool key matching, and the second contains SSL context parameters used to determine connection uniqueness.
        """
        return _urllib3_request_context(request, verify, cert, self.poolmanager)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        """
        Returns a TLS-enabled urllib3 connection pool configured for the given request, with proper certificate verification and optional client authentication. This function is used internally by the HTTPAdapter to establish secure connections while supporting proxy configurations, ensuring that requests are made securely and reliably according to the project's goal of simplifying HTTP interactions with robust security defaults.
        
        Args:
            request: The PreparedRequest object containing the URL and metadata for the outgoing HTTP request.
            verify: Controls TLS certificate verification—True to verify against a trusted CA bundle, False to disable verification, or a path to a custom CA bundle.
            proxies: Optional dictionary mapping protocol schemes to proxy URLs, used to route requests through intermediaries.
            cert: Optional SSL certificate or tuple (certfile, keyfile) for client authentication (mTLS) when required by the server.
        
        Returns:
            A urllib3 ConnectionPool instance configured with the specified TLS settings, ready to send the request securely.
        """
        proxy = select_proxy(request.url, proxies)
        try:
            host_params, pool_kwargs = self.build_connection_pool_key_attributes(
                request,
                verify,
                cert,
            )
        except ValueError as e:
            raise InvalidURL(e, request=request)
        if proxy:
            proxy = prepend_scheme_if_needed(proxy, "http")
            proxy_url = parse_url(proxy)
            if not proxy_url.host:
                raise InvalidProxyURL(
                    "Please check proxy URL. It is malformed "
                    "and could be missing the host."
                )
            proxy_manager = self.proxy_manager_for(proxy)
            conn = proxy_manager.connection_from_host(
                **host_params, pool_kwargs=pool_kwargs
            )
        else:
            # Only scheme should be lower case
            conn = self.poolmanager.connection_from_host(
                **host_params, pool_kwargs=pool_kwargs
            )

        return conn

    def get_connection(self, url, proxies=None):
        """
        DEPRECATED: Users should move to `get_connection_with_tls_context` for all subclasses of HTTPAdapter using Requests>=2.32.2.
        
        This method creates and returns a urllib3 connection pool for the given URL, enabling HTTPAdapter subclasses to manage low-level HTTP connections. It is only exposed for advanced use cases involving custom adapter implementations, as it bypasses higher-level abstractions provided by Requests. The function handles proxy configuration and ensures proper connection setup, but should not be called directly by end users.
        
        Args:
            url: The URL to connect to, used to determine the appropriate connection pool.
            proxies: (optional) A dictionary of proxy settings in Requests format, used to route the connection through specified proxies.
        
        Returns:
            A urllib3 ConnectionPool instance configured for the given URL and proxy settings.
        """
        warnings.warn(
            (
                "`get_connection` has been deprecated in favor of "
                "`get_connection_with_tls_context`. Custom HTTPAdapter subclasses "
                "will need to migrate for Requests>=2.32.2. Please see "
                "https://github.com/psf/requests/pull/6710 for more details."
            ),
            DeprecationWarning,
        )
        proxy = select_proxy(url, proxies)

        if proxy:
            proxy = prepend_scheme_if_needed(proxy, "http")
            proxy_url = parse_url(proxy)
            if not proxy_url.host:
                raise InvalidProxyURL(
                    "Please check proxy URL. It is malformed "
                    "and could be missing the host."
                )
            proxy_manager = self.proxy_manager_for(proxy)
            conn = proxy_manager.connection_from_url(url)
        else:
            # Only scheme should be lower case
            parsed = urlparse(url)
            url = parsed.geturl()
            conn = self.poolmanager.connection_from_url(url)

        return conn

    def close(self):
        """
        Cleans up internal resources by closing all pooled connections.
        
        This ensures proper cleanup of network resources after use, preventing resource leaks and ensuring that connections are properly released. In the context of Requests, this is essential for maintaining efficient and reliable HTTP communication, especially when managing multiple sessions or long-running applications.
        """
        self.poolmanager.clear()
        for proxy in self.proxy_manager.values():
            proxy.clear()

    def request_url(self, request, proxies):
        """
        Determine the appropriate URL to use for the final HTTP request, accounting for proxy configurations.
        
        When sending requests through HTTP proxies, the full URL must be used to ensure the proxy can correctly route the request. For direct connections or SOCKS proxies, only the path portion of the URL is needed to avoid issues with proxy handling. This function ensures compatibility with proxy settings while maintaining correct URL formatting for the underlying HTTP adapter.
        
        Args:
            request: The PreparedRequest being sent, containing the original URL and request metadata.
            proxies: A dictionary mapping URL schemes or schemes and hosts to proxy URLs.
        
        Returns:
            The URL to use for the final request, either the full URL (when proxied) or just the path (when direct or using SOCKS).
        """
        proxy = select_proxy(request.url, proxies)
        scheme = urlparse(request.url).scheme

        is_proxied_http_request = proxy and scheme != "https"
        using_socks_proxy = False
        if proxy:
            proxy_scheme = urlparse(proxy).scheme.lower()
            using_socks_proxy = proxy_scheme.startswith("socks")

        url = request.path_url
        if url.startswith("//"):  # Don't confuse urllib3
            url = f"/{url.lstrip('/')}"

        if is_proxied_http_request and not using_socks_proxy:
            url = urldefragauth(request.url)

        return url

    def add_headers(self, request, **kwargs):
        """
        Add necessary headers to HTTP requests made through the adapter. This method exists to allow customization of request headers when using a custom HTTPAdapter, enabling advanced use cases such as adding authentication tokens, setting custom user agents, or injecting headers required by specific servers. By default, it does nothing, providing a hook for users to extend behavior without modifying core library code.
        
        Args:
            request: The PreparedRequest object to which headers should be added.
            kwargs: Additional keyword arguments passed from the send() method call.
        """
        pass

    def proxy_headers(self, proxy):
        """
        Returns headers required to authenticate with a proxy server when making HTTP requests through a proxy. This ensures that credentials are properly sent to the proxy during connection setup, preventing them from being mistakenly tunnelled in a CONNECT request.
        
        This function is essential for maintaining secure and correct proxy communication in Requests' HTTPAdapter implementation, particularly when dealing with authenticated proxies.
        
        Args:
            proxy: The URL of the proxy server, which may include authentication credentials.
        
        Returns:
            A dictionary containing the Proxy-Authorization header if credentials are present, otherwise an empty dictionary.
        """
        headers = {}
        username, password = get_auth_from_url(proxy)

        if username:
            headers["Proxy-Authorization"] = _basic_auth_str(username, password)

        return headers

    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None
    ):
        """
        Sends an HTTP request using a prepared request object and returns the server's response. This method is central to Requests' mission of simplifying HTTP interactions by abstracting low-level details like connection management, TLS verification, and error handling, allowing developers to focus on building applications without worrying about the complexities of network communication.
        
        Args:
            request: The PreparedRequest object containing the HTTP request details such as method, URL, headers, and body.
            stream: Whether to stream the response content, useful for large downloads or real-time data processing.
            timeout: How long to wait for a response before timing out, either as a single float value or a tuple specifying connect and read timeouts.
            verify: Controls whether SSL certificate verification is performed; can be a boolean or a path to a CA bundle for custom trust settings.
            cert: Optional SSL certificate to use for authentication with the server.
            proxies: Dictionary mapping protocol (e.g., http, https) to proxy URLs for routing requests through intermediaries.
        
        Returns:
            A Response object containing the server's status code, headers, body, and other metadata, enabling easy access to the result of the HTTP request.
        """

        try:
            conn = self.get_connection_with_tls_context(
                request, verify, proxies=proxies, cert=cert
            )
        except LocationValueError as e:
            raise InvalidURL(e, request=request)

        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)
        self.add_headers(
            request,
            stream=stream,
            timeout=timeout,
            verify=verify,
            cert=cert,
            proxies=proxies,
        )

        chunked = not (request.body is None or "Content-Length" in request.headers)

        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
                timeout = TimeoutSauce(connect=connect, read=read)
            except ValueError:
                raise ValueError(
                    f"Invalid timeout {timeout}. Pass a (connect, read) timeout tuple, "
                    f"or a single float to set both timeouts to the same value."
                )
        elif isinstance(timeout, TimeoutSauce):
            pass
        else:
            timeout = TimeoutSauce(connect=timeout, read=timeout)

        try:
            resp = conn.urlopen(
                method=request.method,
                url=url,
                body=request.body,
                headers=request.headers,
                redirect=False,
                assert_same_host=False,
                preload_content=False,
                decode_content=False,
                retries=self.max_retries,
                timeout=timeout,
                chunked=chunked,
            )

        except (ProtocolError, OSError) as err:
            raise ConnectionError(err, request=request)

        except MaxRetryError as e:
            if isinstance(e.reason, ConnectTimeoutError):
                # TODO: Remove this in 3.0.0: see #2811
                if not isinstance(e.reason, NewConnectionError):
                    raise ConnectTimeout(e, request=request)

            if isinstance(e.reason, ResponseError):
                raise RetryError(e, request=request)

            if isinstance(e.reason, _ProxyError):
                raise ProxyError(e, request=request)

            if isinstance(e.reason, _SSLError):
                # This branch is for urllib3 v1.22 and later.
                raise SSLError(e, request=request)

            raise ConnectionError(e, request=request)

        except ClosedPoolError as e:
            raise ConnectionError(e, request=request)

        except _ProxyError as e:
            raise ProxyError(e)

        except (_SSLError, _HTTPError) as e:
            if isinstance(e, _SSLError):
                # This branch is for urllib3 versions earlier than v1.22
                raise SSLError(e, request=request)
            elif isinstance(e, ReadTimeoutError):
                raise ReadTimeout(e, request=request)
            elif isinstance(e, _InvalidHeader):
                raise InvalidHeader(e, request=request)
            else:
                raise

        return self.build_response(request, resp)
