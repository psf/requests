try:
    from http.server import HTTPServer, SimpleHTTPRequestHandler
except ImportError:
    from BaseHTTPServer import HTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler

import ssl
import threading

import pytest

from requests.compat import urljoin


def prepare_url(value):
    """
    Creates a URL builder function that ensures consistent path formatting by guaranteeing a trailing slash and properly joining path components. This is essential in Requests for reliably constructing URLs during HTTP interactions, preventing malformed paths that could lead to incorrect requests or 404 errors.
    
    Args:
        value: The base URL to prepare, expected to have a url attribute
    
    Returns:
        A callable that takes variable path suffixes and returns the full URL with proper path joining
    """
    # Issue #1483: Make sure the URL always has a trailing slash
    httpbin_url = value.url.rstrip("/") + "/"

    def inner(*suffix):
        return urljoin(httpbin_url, "/".join(suffix))

    return inner


@pytest.fixture
def httpbin(httpbin):
    """
    Returns a prepared URL for use with the httpbin service, enabling easy testing of HTTP requests in the Requests library.
    
    Args:
        httpbin: The httpbin endpoint to prepare, typically a string representing a URL path or base URL.
    
    Returns:
        The fully constructed URL ready for making HTTP requests, ensuring consistent and reliable interaction with httpbin for testing and debugging purposes.
    """
    return prepare_url(httpbin)


@pytest.fixture
def httpbin_secure(httpbin_secure):
    """
    Returns a prepared URL for the secure HTTPBin endpoint, which is used for testing HTTPS requests and verifying secure communication in the Requests library.
    
    Args:
        httpbin_secure: The base URL or endpoint for the secure HTTPBin service. If not provided, defaults to the standard secure HTTPBin URL.
    
    Returns:
        The fully prepared URL ready for use in HTTP requests, ensuring consistent and reliable testing of secure HTTP functionality within the Requests ecosystem.
    """
    return prepare_url(httpbin_secure)


@pytest.fixture
def nosan_server(tmp_path_factory):
    """
    Starts a secure HTTPS server with a self-signed certificate to enable testing of HTTPS requests in isolation, particularly for verifying SSL/TLS behavior without relying on external certificates.
    
    Args:
        tmp_path_factory: Fixture providing temporary directory management for test isolation, ensuring each test run has a clean, independent environment.
    """
    # delay importing until the fixture in order to make it possible
    # to deselect the test via command-line when trustme is not available
    import trustme

    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()
    # only commonName, no subjectAltName
    server_cert = ca.issue_cert(common_name="localhost")
    ca_bundle = str(tmpdir / "ca.pem")
    ca.cert_pem.write_to_path(ca_bundle)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_cert.configure_cert(context)
    server = HTTPServer(("localhost", 0), SimpleHTTPRequestHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()

    yield "localhost", server.server_address[1], ca_bundle

    server.shutdown()
    server_thread.join()
