import os
import ssl
import threading
from urllib.parse import urljoin
from wsgiref.handlers import SimpleHandler
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


class ServerHandler(SimpleHandler):
    server_software = "Pytest-HTTPBIN/0.1.0"
    http_version = "1.1"

    def cleanup_headers(self):
        SimpleHandler.cleanup_headers(self)
        self.headers["Connection"] = "Close"

    def close(self):
        try:
            self.request_handler.log_request(
                self.status.split(" ", 1)[0], self.bytes_sent
            )
        finally:
            SimpleHandler.close(self)


class Handler(WSGIRequestHandler):
    def handle(self):
        """Handle a single HTTP request"""

        self.raw_requestline = self.rfile.readline()
        if not self.parse_request():  # An error code has been sent, just exit
            return

        handler = ServerHandler(
            self.rfile, self.wfile, self.get_stderr(), self.get_environ()
        )
        handler.request_handler = self  # backpointer for logging
        handler.run(self.server.get_app())

    def get_environ(self):
        """
        wsgiref simple server adds content-type text/plain to everything, this
        removes it if it's not actually in the headers.
        """
        # Note: Can't use super since this is an oldstyle class in python 2.x
        environ = WSGIRequestHandler.get_environ(self).copy()
        if self.headers.get("content-type") is None:
            del environ["CONTENT_TYPE"]
        return environ


class SecureWSGIServer(WSGIServer):
    def get_request(self):
        socket, address = super().get_request()
        try:
            socket.settimeout(1.0)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(
                os.path.join(CERT_DIR, "server.pem"),
                os.path.join(CERT_DIR, "server.key"),
            )
            return (
                context.wrap_socket(
                    socket, server_side=True, suppress_ragged_eofs=True
                ),
                address,
            )
        except Exception as e:
            print("pytest-httpbin server hit an exception serving request: %s" % e)
            print("attempting to ignore so the rest of the tests can run")
            raise

    def setup_environ(self):
        super().setup_environ()
        self.base_environ["HTTPS"] = "yes"


class Server:
    """
    HTTP server running a WSGI application in its own thread.
    """

    port_envvar = "HTTPBIN_HTTP_PORT"

    def __init__(self, host="127.0.0.1", port=0, application=None, **kwargs):
        self.app = application
        if self.port_envvar in os.environ:
            port = int(os.environ[self.port_envvar])
        self._server = make_server(
            host, port, self.app, handler_class=Handler, **kwargs
        )
        self.host = self._server.server_address[0]
        self.port = self._server.server_address[1]
        self.protocol = "http"

        self._thread = threading.Thread(
            name=self.__class__,
            target=self._server.serve_forever,
        )

    def __del__(self):
        if hasattr(self, "_server"):
            self.stop()

    def start(self):
        self._thread.start()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args, **kwargs):
        self.stop()
        suppress_exc = self._server.__exit__(*args, **kwargs)
        self._thread.join()
        return suppress_exc

    def __add__(self, other):
        return self.url + other

    def stop(self):
        self._server.shutdown()

    @property
    def url(self):
        return f"{self.protocol}://{self.host}:{self.port}"

    def join(self, url, allow_fragments=True):
        return urljoin(self.url, url, allow_fragments=allow_fragments)


class SecureServer(Server):
    port_envvar = "HTTPBIN_HTTPS_PORT"

    def __init__(self, host="127.0.0.1", port=0, application=None, **kwargs):
        kwargs["server_class"] = SecureWSGIServer
        super().__init__(host, port, application, **kwargs)
        self.protocol = "https"
