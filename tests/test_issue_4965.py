import threading

import pytest

import requests
from tests.testserver.server import Server, consume_socket_content


def test_response_content_replays_stream_error():
    """Regression for #4965: repeated content access re-raises stream error."""

    def incomplete_chunked_response_handler(sock):
        consume_socket_content(sock, timeout=0.5)
        sock.send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n")

    close_server = threading.Event()
    server = Server(incomplete_chunked_response_handler)

    with server as (host, port):
        response = requests.get(f"http://{host}:{port}/", stream=True)

        with pytest.raises(requests.exceptions.ChunkedEncodingError):
            response.content

        with pytest.raises(requests.exceptions.ChunkedEncodingError):
            response.content

        close_server.set()
