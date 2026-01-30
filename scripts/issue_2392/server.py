#!/usr/bin/env python
"""
Reproduction server for issue #2392: chunked response that triggers read timeout.

Sends a chunked HTTP response but delays between chunks longer than the client's
read timeout, so the client hits a read timeout while streaming.

Usage:
    python server.py

Then in another terminal run client.py.
"""
import select
import socket
import threading
import time


def consume_socket_content(sock, timeout=0.5):
    chunks = 65536
    content = b""
    while True:
        ready, _, _ = select.select([sock], [], [], timeout)
        if not ready:
            break
        data = sock.recv(chunks)
        if not data:
            break
        content += data
    return content


def slow_chunked_handler(sock):
    consume_socket_content(sock, timeout=0.5)
    # Chunked response: send headers and first chunk
    sock.send(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"5\r\n"
        b"hello\r\n"
    )
    # Wait longer than client read timeout (e.g. 0.5s) so urllib3 raises ReadTimeoutError
    time.sleep(2.0)
    sock.send(b"0\r\n\r\n")


def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 8000))
    server_sock.listen(1)
    print("Server listening on http://127.0.0.1:8000/ (chunked, slow second chunk)")

    while True:
        sock, _ = server_sock.accept()
        try:
            slow_chunked_handler(sock)
        finally:
            sock.close()


if __name__ == "__main__":
    main()
