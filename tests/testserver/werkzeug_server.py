# -*- coding: utf-8 -*-
import multiprocessing
import socket

from werkzeug import Request, Response, run_simple


class WerkzeugServer(object):
    """Realistic WSGI server for unit testing."""

    def __init__(self, application, host='localhost', port=0):
        super(WerkzeugServer, self).__init__()

        self.host = host
        self.port = port

        # Werkzeug will not automatically pick a valid port for us.
        if not self.port:
            sock = socket.socket()
            sock.bind((self.host, self.port))
            self.port = sock.getsockname()[1]

            # Try to close the socket.  Ignore errors.
            try:
                sock.close()
            except IOError:
                pass

        def run_app() -> None:
            run_simple(self.host, self.port, application)         

        self.process = multiprocessing.Process(
            target=run_app)

    @classmethod
    def echo_server(cls):
        @Request.application
        def echo_application(request: Request) -> Response:
            return Response(
                request.get_data(),\
                200,
                content_type=request.content_type)

        return WerkzeugServer(echo_application)

    def __enter__(self):
        self.process.start()
        return self.host, self.port

    def __exit__(self, exc_type, exc_value, traceback):
        self.process.terminate()
        return False
