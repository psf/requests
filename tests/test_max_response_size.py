import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import requests
from requests.adapters import HTTPAdapter


class _TestHandler(BaseHTTPRequestHandler):
    routes = {}

    def do_HEAD(self):
        handler = self.routes.get(("HEAD", self.path))
        if handler is None:
            self.send_response(404)
            self.end_headers()
            return
        handler(self, head_only=True)

    def do_GET(self):
        handler = self.routes.get(("GET", self.path))
        if handler is None:
            self.send_response(404)
            self.end_headers()
            return
        handler(self, head_only=False)

    def log_message(self, fmt, *args):
        return


@pytest.fixture()
def http_server_url():
    server = HTTPServer(("127.0.0.1", 0), _TestHandler)
    host, port = server.server_address
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=2)


def _install_routes(routes):
    _TestHandler.routes = routes


def _run_in_thread(fn, timeout_s=2):
    done = threading.Event()
    out = {"exc": None, "result": None}

    def _wrap():
        try:
            out["result"] = fn()
        except BaseException as e:  # pytest will re-raise below
            out["exc"] = e
        finally:
            done.set()

    t = threading.Thread(target=_wrap, daemon=True)
    t.start()
    assert done.wait(timeout=timeout_s) is True, "operation did not complete (possible connection not released)"
    if out["exc"] is not None:
        raise out["exc"]
    return out["result"]


def test_default_behavior_unchanged_without_max_response_size(http_server_url):
    body = b"ok-" * 40

    def handle(self, head_only):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    _install_routes({("GET", "/default"): handle})

    r = requests.get(f"{http_server_url}/default")
    assert r.status_code == 200
    assert r.content == body


def test_requests_request_accepts_max_response_size(http_server_url):
    body = b"q" * 50

    def handle(self, head_only):
        self.send_response(200)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    _install_routes({("GET", "/request"): handle})

    with pytest.raises(requests.exceptions.ContentTooLarge):
        requests.request("GET", f"{http_server_url}/request", max_response_size=10)


def test_session_request_accepts_max_response_size(http_server_url):
    body = b"s" * 50

    def handle(self, head_only):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    _install_routes({("GET", "/session"): handle})

    with requests.Session() as sess:
        with pytest.raises(requests.exceptions.ContentTooLarge):
            sess.request("GET", f"{http_server_url}/session", max_response_size=10)


def test_non_streaming_rejects_when_body_exceeds_limit(http_server_url):
    body = b"x" * 50

    def handle(self, head_only):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    _install_routes({("GET", "/len"): handle})

    with pytest.raises(requests.exceptions.ContentTooLarge):
        requests.get(f"{http_server_url}/len", max_response_size=10)


def test_non_streaming_rejects_without_content_length(http_server_url):
    body = b"y" * 50

    def handle(self, head_only):
        self.send_response(200)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    _install_routes({("GET", "/nolength"): handle})

    with pytest.raises(requests.exceptions.ContentTooLarge):
        requests.get(f"{http_server_url}/nolength", max_response_size=10)


def test_streaming_raises_during_iter_content(http_server_url):
    body = b"a" * 30

    def handle(self, head_only):
        self.send_response(200)
        self.end_headers()
        if not head_only:
            self.wfile.write(body[:15])
            self.wfile.flush()
            self.wfile.write(body[15:])

    _install_routes({("GET", "/stream"): handle})

    r = requests.get(f"{http_server_url}/stream", stream=True, max_response_size=20)

    with pytest.raises(requests.exceptions.ContentTooLarge):
        b"".join(r.iter_content(chunk_size=8))


def test_streaming_content_property_raises(http_server_url):
    body = b"b" * 25

    def handle(self, head_only):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    _install_routes({("GET", "/content"): handle})

    r = requests.get(f"{http_server_url}/content", stream=True, max_response_size=10)

    with pytest.raises(requests.exceptions.ContentTooLarge):
        _ = r.content


def test_head_smaller_than_get_is_enforced(http_server_url):
    head_len = 5
    body = b"z" * 40

    def handle_head(self, head_only):
        self.send_response(200)
        self.send_header("Content-Length", str(head_len))
        self.end_headers()

    def handle_get(self, head_only):
        self.send_response(200)
        self.send_header("Content-Length", str(head_len))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    _install_routes(
        {
            ("HEAD", "/mismatch"): handle_head,
            ("GET", "/mismatch"): handle_get,
        }
    )

    r = requests.get(f"{http_server_url}/mismatch", stream=True, max_response_size=10)

    with pytest.raises(requests.exceptions.ContentTooLarge):
        b"".join(r.iter_content(chunk_size=16))


def test_connection_is_released_or_closed_after_streaming_limit_exceeded(http_server_url):
    big = b"k" * 200_000
    ok = b"OK"

    def handle_big(self, head_only):
        self.send_response(200)
        self.end_headers()
        if not head_only:
            # write a large body so the client will hit the limit during consumption
            self.wfile.write(big)

    def handle_ok(self, head_only):
        self.send_response(200)
        self.send_header("Content-Length", str(len(ok)))
        self.end_headers()
        if not head_only:
            self.wfile.write(ok)

    _install_routes(
        {
            ("GET", "/big"): handle_big,
            ("GET", "/ok"): handle_ok,
        }
    )

    with requests.Session() as sess:
        # 1-connection pool; if the first connection isn't released/closed after the exception,
        # the second request will block waiting for a free connection.
        sess.mount("http://", HTTPAdapter(pool_connections=1, pool_maxsize=1, pool_block=True))

        r = sess.get(f"{http_server_url}/big", stream=True, max_response_size=1024)

        with pytest.raises(requests.exceptions.ContentTooLarge):
            b"".join(r.iter_content(chunk_size=512))

        def _second_request():
            return sess.get(f"{http_server_url}/ok").content

        assert _run_in_thread(_second_request, timeout_s=2) == ok
