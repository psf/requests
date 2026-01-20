import threading

import pytest
from tests.testserver.server import Server, consume_socket_content

import requests
from requests.compat import JSONDecodeError

from .utils import override_environ


def echo_response_handler(sock):
    """
    Handles incoming HTTP requests by echoing the request content back to the client, enabling testing and debugging of HTTP communication flows.
    
    Args:
        sock: The socket connection representing the client request, used to read incoming data and send the response.
    """
    request_content = consume_socket_content(sock, timeout=0.5)

    text_200 = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: %d\r\n\r\n"
        b"%s"
    ) % (len(request_content), request_content)
    sock.send(text_200)


def test_chunked_upload():
    """
    Tests that Requests can safely handle generator objects as request data, ensuring proper chunked transfer encoding during uploads.
    
    This test verifies the library's ability to work seamlessly with iterable data sources (like generators) in POST requests, which is essential for efficient, memory-safe uploads of large or streaming data. By confirming that the Transfer-Encoding header is set to 'chunked' and the server receives the data correctly, it ensures Requests maintains its core purpose of providing a reliable, high-level HTTP interface that abstracts complexity while supporting modern web protocols.
    """
    close_server = threading.Event()
    server = Server.basic_response_server(wait_to_close_event=close_server)
    data = iter([b"a", b"b", b"c"])

    with server as (host, port):
        url = f"http://{host}:{port}/"
        r = requests.post(url, data=data, stream=True)
        close_server.set()  # release server block

    assert r.status_code == 200
    assert r.request.headers["Transfer-Encoding"] == "chunked"


def test_chunked_encoding_error():
    """
    Verifies that Requests correctly raises a ChunkedEncodingError when the server sends an incomplete chunked transfer encoding response, ensuring robust handling of malformed server responses.
    
    Returns:
        None
    """

    def incomplete_chunked_response_handler(sock):
        request_content = consume_socket_content(sock, timeout=0.5)

        # The server never ends the request and doesn't provide any valid chunks
        sock.send(
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
        )

        return request_content

    close_server = threading.Event()
    server = Server(incomplete_chunked_response_handler)

    with server as (host, port):
        url = f"http://{host}:{port}/"
        with pytest.raises(requests.exceptions.ChunkedEncodingError):
            requests.get(url)
        close_server.set()  # release server block


def test_chunked_upload_uses_only_specified_host_header():
    """
    Verify that chunked uploads respect the explicitly provided Host header, ensuring correct request construction when custom headers are specified. This test is critical for maintaining compatibility with servers that rely on accurate Host header values during chunked transfer encoding, which aligns with Requests' goal of accurately representing user intent in HTTP requests.
    """
    close_server = threading.Event()
    server = Server(echo_response_handler, wait_to_close_event=close_server)

    data = iter([b"a", b"b", b"c"])
    custom_host = "sample-host"

    with server as (host, port):
        url = f"http://{host}:{port}/"
        r = requests.post(url, data=data, headers={"Host": custom_host}, stream=True)
        close_server.set()  # release server block

    expected_header = b"Host: %s\r\n" % custom_host.encode("utf-8")
    assert expected_header in r.content
    assert r.content.count(b"Host: ") == 1


def test_chunked_upload_doesnt_skip_host_header():
    """
    Ensure the Host header is properly included in chunked upload requests to maintain correct HTTP semantics and prevent server-side issues.
    
    This test verifies that Requests correctly preserves the Host header when sending chunked transfer-encoded data, which is critical for proper server routing and request handling. Without this header, servers may fail to process the request or route it incorrectly, especially in environments where virtual hosting is used. The test confirms that only one Host header is sent and that it matches the expected host and port, ensuring compliance with HTTP/1.1 standards and reliable communication with web servers.
    """
    close_server = threading.Event()
    server = Server(echo_response_handler, wait_to_close_event=close_server)

    data = iter([b"a", b"b", b"c"])

    with server as (host, port):
        expected_host = f"{host}:{port}"
        url = f"http://{host}:{port}/"
        r = requests.post(url, data=data, stream=True)
        close_server.set()  # release server block

    expected_header = b"Host: %s\r\n" % expected_host.encode("utf-8")
    assert expected_header in r.content
    assert r.content.count(b"Host: ") == 1


def test_conflicting_content_lengths():
    """
    Verifies that Requests correctly raises an InvalidHeader exception when encountering multiple conflicting Content-Length headers in a response, ensuring robustness against malformed or malicious server responses.
    
    Returns:
        None
    """

    def multiple_content_length_response_handler(sock):
        request_content = consume_socket_content(sock, timeout=0.5)
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 16\r\n"
            b"Content-Length: 32\r\n\r\n"
            b"-- Bad Actor -- Original Content\r\n"
        )
        sock.send(response)

        return request_content

    close_server = threading.Event()
    server = Server(multiple_content_length_response_handler)

    with server as (host, port):
        url = f"http://{host}:{port}/"
        with pytest.raises(requests.exceptions.InvalidHeader):
            requests.get(url)
        close_server.set()


def test_digestauth_401_count_reset_on_redirect():
    """
    Test that the digest authentication counter is properly reset after a successful authentication followed by a 302 redirect to another digest challenge.
    
    This ensures Requests correctly handles the state of authentication attempts during redirects, preventing incorrect retry behavior when multiple digest challenges occur in sequence. This is critical for maintaining secure and reliable authentication flows in real-world scenarios where servers may redirect clients to different endpoints requiring re-authentication.
    
    Returns:
        None
    """
    text_401 = (b'HTTP/1.1 401 UNAUTHORIZED\r\n'
                b'Content-Length: 0\r\n'
                b'WWW-Authenticate: Digest nonce="6bf5d6e4da1ce66918800195d6b9130d"'
                b', opaque="372825293d1c26955496c80ed6426e9e", '
                b'realm="me@kennethreitz.com", qop=auth\r\n\r\n')

    text_302 = (b'HTTP/1.1 302 FOUND\r\n'
                b'Content-Length: 0\r\n'
                b'Location: /\r\n\r\n')

    text_200 = (b'HTTP/1.1 200 OK\r\n'
                b'Content-Length: 0\r\n\r\n')

    expected_digest = (b'Authorization: Digest username="user", '
                       b'realm="me@kennethreitz.com", '
                       b'nonce="6bf5d6e4da1ce66918800195d6b9130d", uri="/"')

    auth = requests.auth.HTTPDigestAuth('user', 'pass')

    def digest_response_handler(sock):
        # Respond to initial GET with a challenge.
        request_content = consume_socket_content(sock, timeout=0.5)
        assert request_content.startswith(b"GET / HTTP/1.1")
        sock.send(text_401)

        # Verify we receive an Authorization header in response, then redirect.
        request_content = consume_socket_content(sock, timeout=0.5)
        assert expected_digest in request_content
        sock.send(text_302)

        # Verify Authorization isn't sent to the redirected host,
        # then send another challenge.
        request_content = consume_socket_content(sock, timeout=0.5)
        assert b'Authorization:' not in request_content
        sock.send(text_401)

        # Verify Authorization is sent correctly again, and return 200 OK.
        request_content = consume_socket_content(sock, timeout=0.5)
        assert expected_digest in request_content
        sock.send(text_200)

        return request_content

    close_server = threading.Event()
    server = Server(digest_response_handler, wait_to_close_event=close_server)

    with server as (host, port):
        url = f'http://{host}:{port}/'
        r = requests.get(url, auth=auth)
        # Verify server succeeded in authenticating.
        assert r.status_code == 200
        # Verify Authorization was sent in final request.
        assert 'Authorization' in r.request.headers
        assert r.request.headers['Authorization'].startswith('Digest ')
        # Verify redirect happened as we expected.
        assert r.history[0].status_code == 302
        close_server.set()


def test_digestauth_401_only_sent_once():
    """
    Verify that HTTP Digest Authentication sends the Authorization header only once in response to a 401 challenge, preventing repeated authentication attempts.
    
    This ensures the client behaves correctly under the HTTP authentication protocol, where repeated challenges should not trigger additional responses after the initial authentication attempt. This behavior maintains security and efficiency by avoiding unnecessary retries.
    
    Returns:
        None
    """
    text_401 = (b'HTTP/1.1 401 UNAUTHORIZED\r\n'
                b'Content-Length: 0\r\n'
                b'WWW-Authenticate: Digest nonce="6bf5d6e4da1ce66918800195d6b9130d"'
                b', opaque="372825293d1c26955496c80ed6426e9e", '
                b'realm="me@kennethreitz.com", qop=auth\r\n\r\n')

    expected_digest = (b'Authorization: Digest username="user", '
                       b'realm="me@kennethreitz.com", '
                       b'nonce="6bf5d6e4da1ce66918800195d6b9130d", uri="/"')

    auth = requests.auth.HTTPDigestAuth('user', 'pass')

    def digest_failed_response_handler(sock):
        # Respond to initial GET with a challenge.
        request_content = consume_socket_content(sock, timeout=0.5)
        assert request_content.startswith(b"GET / HTTP/1.1")
        sock.send(text_401)

        # Verify we receive an Authorization header in response, then
        # challenge again.
        request_content = consume_socket_content(sock, timeout=0.5)
        assert expected_digest in request_content
        sock.send(text_401)

        # Verify the client didn't respond to second challenge.
        request_content = consume_socket_content(sock, timeout=0.5)
        assert request_content == b''

        return request_content

    close_server = threading.Event()
    server = Server(digest_failed_response_handler, wait_to_close_event=close_server)

    with server as (host, port):
        url = f'http://{host}:{port}/'
        r = requests.get(url, auth=auth)
        # Verify server didn't authenticate us.
        assert r.status_code == 401
        assert r.history[0].status_code == 401
        close_server.set()


def test_digestauth_only_on_4xx():
    """
    Ensures that HTTP Digest Authentication is only sent in response to 4xx challenge responses, preventing unnecessary authentication attempts on successful 200 responses.
    
    This behavior aligns with the HTTP specification and improves security and efficiency by avoiding authentication headers when they are not required. It addresses a specific issue where clients incorrectly sent DigestAuth credentials on 200 responses, which could expose credentials unnecessarily.
    
    Returns:
        None
    """
    text_200_chal = (b'HTTP/1.1 200 OK\r\n'
                     b'Content-Length: 0\r\n'
                     b'WWW-Authenticate: Digest nonce="6bf5d6e4da1ce66918800195d6b9130d"'
                     b', opaque="372825293d1c26955496c80ed6426e9e", '
                     b'realm="me@kennethreitz.com", qop=auth\r\n\r\n')

    auth = requests.auth.HTTPDigestAuth('user', 'pass')

    def digest_response_handler(sock):
        # Respond to GET with a 200 containing www-authenticate header.
        request_content = consume_socket_content(sock, timeout=0.5)
        assert request_content.startswith(b"GET / HTTP/1.1")
        sock.send(text_200_chal)

        # Verify the client didn't respond with auth.
        request_content = consume_socket_content(sock, timeout=0.5)
        assert request_content == b''

        return request_content

    close_server = threading.Event()
    server = Server(digest_response_handler, wait_to_close_event=close_server)

    with server as (host, port):
        url = f'http://{host}:{port}/'
        r = requests.get(url, auth=auth)
        # Verify server didn't receive auth from us.
        assert r.status_code == 200
        assert len(r.history) == 0
        close_server.set()


_schemes_by_var_prefix = [
    ('http', ['http']),
    ('https', ['https']),
    ('all', ['http', 'https']),
]

_proxy_combos = []
for prefix, schemes in _schemes_by_var_prefix:
    for scheme in schemes:
        _proxy_combos.append((f"{prefix}_proxy", scheme))

_proxy_combos += [(var.upper(), scheme) for var, scheme in _proxy_combos]


@pytest.mark.parametrize("var,scheme", _proxy_combos)
def test_use_proxy_from_environment(httpbin, var, scheme):
    """
    Tests that Requests correctly respects proxy settings from environment variables when making HTTP requests.
    
    This ensures that users can configure proxies globally via environment variables (like HTTP_PROXY or HTTPS_PROXY), which is essential for scenarios such as network monitoring, debugging, or accessing services through corporate firewalls. The test verifies that Requests properly reads these variables and routes traffic through the specified proxy, even when the proxy is unreachable (simulated with a fake server).
    
    Args:
        httpbin: Fixture that provides a URL to the httpbin service for testing.
        var: Name of the environment variable to set (e.g., 'HTTP_PROXY' or 'HTTPS_PROXY').
        scheme: Protocol scheme to use (e.g., 'http' or 'https') for the request URL.
    """
    url = f"{scheme}://httpbin.org"
    fake_proxy = Server()  # do nothing with the requests; just close the socket
    with fake_proxy as (host, port):
        proxy_url = f"socks5://{host}:{port}"
        kwargs = {var: proxy_url}
        with override_environ(**kwargs):
            # fake proxy's lack of response will cause a ConnectionError
            with pytest.raises(requests.exceptions.ConnectionError):
                requests.get(url)

        # the fake proxy received a request
        assert len(fake_proxy.handler_results) == 1

        # it had actual content (not checking for SOCKS protocol for now)
        assert len(fake_proxy.handler_results[0]) > 0


def test_redirect_rfc1808_to_non_ascii_location():
    """
    Tests that Requests correctly handles non-ASCII characters in redirect URLs according to RFC 1808, ensuring proper UTF-8 percent-encoding of paths in the Location header.
    
    This is critical for the library's reliability when interacting with real-world web servers that may return redirects with internationalized paths. The test verifies that Requests properly encodes non-ASCII characters (like 'š' as '%C5%A1') in redirect URLs and follows the redirect correctly, maintaining compliance with web standards and ensuring consistent behavior across different locales and server implementations.
    """
    path = 'š'
    expected_path = b'%C5%A1'
    redirect_request = []  # stores the second request to the server

    def redirect_resp_handler(sock):
        consume_socket_content(sock, timeout=0.5)
        location = f'//{host}:{port}/{path}'
        sock.send(
            (
                b'HTTP/1.1 301 Moved Permanently\r\n'
                b'Content-Length: 0\r\n'
                b'Location: %s\r\n'
                b'\r\n'
            ) % location.encode('utf8')
        )
        redirect_request.append(consume_socket_content(sock, timeout=0.5))
        sock.send(b'HTTP/1.1 200 OK\r\n\r\n')

    close_server = threading.Event()
    server = Server(redirect_resp_handler, wait_to_close_event=close_server)

    with server as (host, port):
        url = f'http://{host}:{port}'
        r = requests.get(url=url, allow_redirects=True)
        assert r.status_code == 200
        assert len(r.history) == 1
        assert r.history[0].status_code == 301
        assert redirect_request[0].startswith(b'GET /' + expected_path + b' HTTP/1.1')
        assert r.url == '{}/{}'.format(url, expected_path.decode('ascii'))

        close_server.set()


def test_fragment_not_sent_with_request():
    """
    Verify that the fragment portion of a URI is not transmitted to the server during HTTP requests, ensuring compliance with the HTTP specification and maintaining user privacy by preventing sensitive fragment data (such as tokens or view states) from being sent over the network.
    
    This test is critical for Requests' purpose of providing a reliable and secure HTTP client, as it confirms that the library correctly adheres to the standard behavior of excluding fragments from actual requests—since fragments are meant for client-side navigation and are not part of the HTTP request sent to the server.
    """
    close_server = threading.Event()
    server = Server(echo_response_handler, wait_to_close_event=close_server)

    with server as (host, port):
        url = f'http://{host}:{port}/path/to/thing/#view=edit&token=hunter2'
        r = requests.get(url)
        raw_request = r.content

        assert r.status_code == 200
        headers, body = raw_request.split(b'\r\n\r\n', 1)
        status_line, headers = headers.split(b'\r\n', 1)

        assert status_line == b'GET /path/to/thing/ HTTP/1.1'
        for frag in (b'view', b'edit', b'token', b'hunter2'):
            assert frag not in headers
            assert frag not in body

        close_server.set()


def test_fragment_update_on_redirect():
    """
    Verify that when following redirects, the client preserves and propagates the fragment from the original URL only if the target location doesn't already include one. This ensures correct behavior when navigating between URLs with fragments, maintaining user intent while respecting explicit fragment specifications in redirect targets. This is critical for maintaining stateful navigation in web applications, especially when dealing with in-page anchors or client-side routing.
    """

    def response_handler(sock):
        consume_socket_content(sock, timeout=0.5)
        sock.send(
            b'HTTP/1.1 302 FOUND\r\n'
            b'Content-Length: 0\r\n'
            b'Location: /get#relevant-section\r\n\r\n'
        )
        consume_socket_content(sock, timeout=0.5)
        sock.send(
            b'HTTP/1.1 302 FOUND\r\n'
            b'Content-Length: 0\r\n'
            b'Location: /final-url/\r\n\r\n'
        )
        consume_socket_content(sock, timeout=0.5)
        sock.send(
            b'HTTP/1.1 200 OK\r\n\r\n'
        )

    close_server = threading.Event()
    server = Server(response_handler, wait_to_close_event=close_server)

    with server as (host, port):
        url = f'http://{host}:{port}/path/to/thing/#view=edit&token=hunter2'
        r = requests.get(url)

        assert r.status_code == 200
        assert len(r.history) == 2
        assert r.history[0].request.url == url

        # Verify we haven't overwritten the location with our previous fragment.
        assert r.history[1].request.url == f'http://{host}:{port}/get#relevant-section'
        # Verify previous fragment is used and not the original.
        assert r.url == f'http://{host}:{port}/final-url/#relevant-section'

        close_server.set()


def test_json_decode_compatibility_for_alt_utf_encodings():
    """
    Tests that Requests gracefully handles responses with non-UTF-8 encodings like UTF-16 with BOM by raising a JSONDecodeError without attempting to decode invalid encodings, ensuring robust error handling in real-world scenarios where servers may return improperly encoded JSON.
    
    This test is critical for Requests' purpose of providing reliable, user-friendly HTTP interactions: it verifies that the library correctly detects and rejects invalid JSON encodings without leaking raw response text in error messages, preventing potential security risks and ensuring predictable behavior when consuming APIs that may inconsistently encode their responses.
    """

    def response_handler(sock):
        consume_socket_content(sock, timeout=0.5)
        sock.send(
            b'HTTP/1.1 200 OK\r\n'
            b'Content-Length: 18\r\n\r\n'
            b'\xff\xfe{\x00"\x00K0"\x00=\x00"\x00\xab0"\x00\r\n'
        )

    close_server = threading.Event()
    server = Server(response_handler, wait_to_close_event=close_server)

    with server as (host, port):
        url = f'http://{host}:{port}/'
        r = requests.get(url)
    r.encoding = None
    with pytest.raises(requests.exceptions.JSONDecodeError) as excinfo:
        r.json()
    assert isinstance(excinfo.value, requests.exceptions.RequestException)
    assert isinstance(excinfo.value, JSONDecodeError)
    assert r.text not in str(excinfo.value)
