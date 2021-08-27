# -*- coding: utf-8 -*-
import multiprocessing
import socket
import time

from werkzeug import Request, Response, run_simple


@Request.application
def echo_application(request):
    return Response(
        request.get_data(),
        200,
        content_type=request.content_type)


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

        self.process = multiprocessing.Process(
            target=run_simple,
            args=(self.host, self.port, application))

    @classmethod
    def echo_server(cls):
        return WerkzeugServer(echo_application)

    def __enter__(self):
        self.process.start()
        time.sleep(15)
        return self.host, self.port

    def __exit__(self, exc_type, exc_value, traceback):
        self.process.terminate()
        return False
