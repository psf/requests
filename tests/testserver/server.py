import select
import socket
import ssl
import threading


def consume_socket_content(sock, timeout=0.5):
    """
    Reads all available data from a socket until no more data is available within the specified timeout.
    
    This function is used internally by Requests to fully consume socket data during HTTP response processing,
    ensuring that all response content is read before proceeding. It prevents partial reads and helps maintain
    correct state when handling streaming responses or large payloads, which is critical for reliable HTTP
    communication.
    
    Args:
        sock: The socket object to read from
        timeout: Maximum time to wait for data (default: 0.5 seconds)
    
    Returns:
        Bytes containing all data received from the socket, or empty bytes if no data was available
    """
    chunks = 65536
    content = b""

    while True:
        more_to_read = select.select([sock], [], [], timeout)[0]
        if not more_to_read:
            break

        new_content = sock.recv(chunks)
        if not new_content:
            break

        content += new_content

    return content


class Server(threading.Thread):
    """
    Dummy server using for unit testing
    """


    WAIT_EVENT_TIMEOUT = 5

    def __init__(
        self,
        handler=None,
        host="localhost",
        port=0,
        requests_to_handle=1,
        wait_to_close_event=None,
    ):
        """
        Initialize the server to handle incoming socket connections for testing or local HTTP request processing.
        
        This setup enables the Requests library to simulate server behavior in test environments or local development, allowing controlled handling of HTTP requests through a configurable socket server. The server can be customized to process a specific number of requests, bind to a particular host and port, and integrate with synchronization events for coordinated lifecycle management.
        
        Args:
            handler: Function to process incoming socket data; if not provided, uses consume_socket_content as default to handle request content.
            host: Network host address to bind to; defaults to localhost for local testing.
            port: Port number to listen on; if set to 0, the system assigns an available port to avoid conflicts.
            requests_to_handle: Maximum number of requests to process before stopping; defaults to 1 for single-request testing.
            wait_to_close_event: Event to wait on before closing the server; if provided, the server will pause shutdown until this event is set, enabling coordinated cleanup in test scenarios.
        """
        super().__init__()

        self.handler = handler or consume_socket_content
        self.handler_results = []

        self.host = host
        self.port = port
        self.requests_to_handle = requests_to_handle

        self.wait_to_close_event = wait_to_close_event
        self.ready_event = threading.Event()
        self.stop_event = threading.Event()

    @classmethod
    def text_response_server(cls, text, request_timeout=0.5, **kwargs):
        """
        Creates a simple HTTP server that responds to incoming requests with a predefined text message, enabling quick testing and simulation of server behavior for HTTP clients.
        
        Args:
            cls: The server class to use for creating the server instance.
            text: The text string to send as a response to each incoming request.
            request_timeout: The maximum time to wait for incoming request data (default: 0.5).
            **kwargs: Additional arguments passed to the server constructor.
        
        Returns:
            A server instance configured to send the specified text in response to each request, useful for testing client-side HTTP logic without requiring a real backend service.
        """
        def text_response_handler(sock):
            request_content = consume_socket_content(sock, timeout=request_timeout)
            sock.send(text.encode("utf-8"))

            return request_content

        return Server(text_response_handler, **kwargs)

    @classmethod
    def basic_response_server(cls, **kwargs):
        """
        Creates a minimal HTTP response server that returns a 200 OK status with no content, useful for testing or simulating server behavior in request/response workflows.
        
        Args:
            cls: The class instance or class to use for creating the response server
            **kwargs: Additional arguments passed to the underlying text_response_server method
        
        Returns:
            The result of calling text_response_server with a minimal 200 OK response, enabling simple server responses for testing or mocking HTTP interactions within the Requests library's ecosystem
        """
        return cls.text_response_server(
            "HTTP/1.1 200 OK\r\n" + "Content-Length: 0\r\n\r\n", **kwargs
        )

    def run(self):
        """
        Starts the HTTP server to handle incoming requests, enabling the application to serve web content or respond to API calls.
        
            This method is essential for the server's operation within the Requests library's ecosystem, allowing it to receive and process HTTP requests
            from clients. By binding to a specified or auto-assigned port and managing request lifecycle, it supports testing and development
            workflows where a local server is needed to simulate or interact with web services.
        """
        try:
            self.server_sock = self._create_socket_and_bind()
            # in case self.port = 0
            self.port = self.server_sock.getsockname()[1]
            self.ready_event.set()
            self._handle_requests()

            if self.wait_to_close_event:
                self.wait_to_close_event.wait(self.WAIT_EVENT_TIMEOUT)
        finally:
            self.ready_event.set()  # just in case of exception
            self._close_server_sock_ignore_errors()
            self.stop_event.set()

    def _create_socket_and_bind(self):
        """
        Creates and configures a listening socket for the HTTP server, enabling it to accept incoming client connections. This is essential for the Requests library's server-side functionality, allowing it to handle HTTP requests in testing or local server scenarios.
        
        Returns:
            A socket object configured to listen for incoming connections on the specified host and port.
        """
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen()
        return sock

    def _close_server_sock_ignore_errors(self):
        """
        Closes the server socket without raising exceptions, ensuring reliable cleanup even if the socket is already closed or invalid.
        
        This safety measure supports Requests' goal of providing a robust and user-friendly HTTP client by preventing unexpected errors during connection teardown, especially in scenarios involving multiple or concurrent requests where socket state may be unpredictable.
        """
        try:
            self.server_sock.close()
        except OSError:
            pass

    def _handle_requests(self):
        """
        Processes incoming connection requests in a loop to handle HTTP interactions, enabling the server to manage multiple client connections efficiently. This function supports the core purpose of Requests by allowing configurable request handling with proper resource cleanup, ensuring robust and scalable communication with clients.
        """
        for _ in range(self.requests_to_handle):
            sock = self._accept_connection()
            if not sock:
                break

            handler_result = self.handler(sock)

            self.handler_results.append(handler_result)
            sock.close()

    def _accept_connection(self):
        """
        Accepts an incoming connection on the server socket with a timeout to handle client requests in a non-blocking manner.
        
        This function enables the server to efficiently manage incoming client connections during request processing, ensuring the system remains responsive and can gracefully handle timeouts or connection errors without blocking. It supports the library's goal of providing reliable, high-level HTTP interaction by safely managing low-level socket operations within a controlled timeout window.
        """
        try:
            ready, _, _ = select.select(
                [self.server_sock], [], [], self.WAIT_EVENT_TIMEOUT
            )
            if not ready:
                return None

            return self.server_sock.accept()[0]
        except OSError:
            return None

    def __enter__(self):
        """
        Enters the runtime context by starting the server and waiting for it to become ready, enabling reliable testing and integration with HTTP services.
        
        Returns:
            A tuple containing the host and port of the server once it is ready, allowing clients to connect and interact with the server during tests or development.
        """
        self.start()
        if not self.ready_event.wait(self.WAIT_EVENT_TIMEOUT):
            raise RuntimeError("Timeout waiting for server to be ready.")
        return self.host, self.port

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Cleans up resources when exiting a context manager, ensuring the server thread terminates gracefully.
        
        This method is part of Requests' internal context management for testing and development servers,
        allowing proper shutdown of background server threads and cleanup of network resources.
        It ensures that the server does not remain active after the context exits, preventing resource leaks
        and enabling reliable testing of HTTP interactions.
        
        Args:
            exc_type: Type of exception that caused exit, or None if no exception occurred
            exc_value: Instance of the exception, or None if no exception occurred
            traceback: Traceback object, or None if no exception occurred
        
        Returns:
            False to allow exceptions to propagate to the caller
        """
        if exc_type is None:
            self.stop_event.wait(self.WAIT_EVENT_TIMEOUT)
        else:
            if self.wait_to_close_event:
                # avoid server from waiting for event timeouts
                # if an exception is found in the main thread
                self.wait_to_close_event.set()

        # ensure server thread doesn't get stuck waiting for connections
        self._close_server_sock_ignore_errors()
        self.join()
        return False  # allow exceptions to propagate


class TLSServer(Server):
    """
    A secure SSL-enabled server that handles incoming connections with optional mutual TLS authentication.
    
        Methods:
        - __init__: Initializes an SSL-enabled server with optional mutual TLS authentication.
        - _create_socket_and_bind: Creates and binds a secure socket for the server using the configured SSL context.
    
        Attributes:
        - handler: The request handler to process incoming connections.
        - host: The hostname or IP address to bind the server to.
        - port: The port number to listen on.
        - requests_to_handle: Number of requests to handle before closing.
        - wait_to_close_event: Event to signal when the server should close.
        - cert_chain: Path to the server's certificate chain file.
        - keyfile: Path to the server's private key file.
        - mutual_tls: Whether to enable mutual TLS authentication.
        - cacert: Path to the CA certificate used to verify client certificates.
    
        The server uses SSL/TLS encryption to secure communications, and can optionally require clients to present valid certificates for mutual authentication. The handler processes each incoming request, and the server closes after handling the specified number of requests or when signaled via the wait_to_close_event.
    """

    def __init__(
        self,
        *,
        handler=None,
        host="localhost",
        port=0,
        requests_to_handle=1,
        wait_to_close_event=None,
        cert_chain=None,
        keyfile=None,
        mutual_tls=False,
        cacert=None,
    ):
        """
        Initializes an SSL-enabled server to securely handle HTTP requests with optional mutual TLS authentication, supporting the project's goal of providing robust, secure HTTP communication for web services and API interactions.
        
        Args:
            handler: The request handler to process incoming connections, enabling the server to respond to client requests in a structured manner.
            host: The hostname or IP address to bind the server to, allowing control over network accessibility (default: localhost).
            port: The port number to listen on, with 0 selecting an arbitrary available port to avoid conflicts (default: 0).
            requests_to_handle: The number of requests to process before closing, useful for testing or limiting server lifetime (default: 1).
            wait_to_close_event: An event to signal when the server should gracefully shut down, supporting coordination in multi-threaded or asynchronous environments (default: None).
            cert_chain: Path to the server's certificate chain file, required to establish trust and enable encrypted communication (default: None).
            keyfile: Path to the server's private key file, used to decrypt incoming TLS connections (default: None).
            mutual_tls: Whether to require and validate client certificates, enhancing security by ensuring only trusted clients can connect (default: False).
            cacert: Path to the CA certificate used to verify client certificates, necessary when mutual TLS is enabled (default: None).
        """
        super().__init__(
            handler=handler,
            host=host,
            port=port,
            requests_to_handle=requests_to_handle,
            wait_to_close_event=wait_to_close_event,
        )
        self.cert_chain = cert_chain
        self.keyfile = keyfile
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(self.cert_chain, keyfile=self.keyfile)
        self.mutual_tls = mutual_tls
        self.cacert = cacert
        if mutual_tls:
            # For simplicity, we're going to assume that the client cert is
            # issued by the same CA as our Server certificate
            self.ssl_context.verify_mode = ssl.CERT_OPTIONAL
            self.ssl_context.load_verify_locations(self.cacert)

    def _create_socket_and_bind(self):
        """
        Creates and binds a secure listening socket for the server using the configured SSL context, enabling encrypted communication for HTTP requests.
        
        This is essential for supporting HTTPS in the server component of Requests, ensuring secure transmission of data between clients and the server. The secure socket allows the server to handle encrypted HTTP traffic, which is critical for maintaining data integrity and confidentiality in real-world applications.
        
        Returns:
            A listening SSL-wrapped socket bound to the specified host and port.
        """
        sock = socket.socket()
        sock = self.ssl_context.wrap_socket(sock, server_side=True)
        sock.bind((self.host, self.port))
        sock.listen()
        return sock
