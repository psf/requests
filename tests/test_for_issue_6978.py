import pytest
import requests
from requests.exceptions import SSLError
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import threading
import os

# Create a custom request handler to serve a GET request
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"")

# Use a mock server with a self-signed certificate and incomplete chain
@pytest.fixture(scope="session")
def incomplete_cert_server():
    """Starts a mock HTTPS server with an incomplete cert chain for testing."""
    # This part of the code would require you to generate a specific
    # certificate and key to simulate the bug. For the sake of this example,
    # we'll use placeholder files. You would replace these with your actual files.
    server_address = ('localhost', 8443)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)

    # Corrected method to create a server-side SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        certfile=os.path.join(os.path.dirname(__file__), "certs", "server-leaf-cert.pem"), # Replace with your server's leaf cert
        keyfile=os.path.join(os.path.dirname(__file__), "certs", "server-key.pem") # Replace with your server's key
    )
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    yield server_address

    httpd.shutdown()

def test_incomplete_chain_connects(incomplete_cert_server):
    """
    Tests that requests connects when provided a trusted leaf cert,
    even if the server's chain is incomplete.
    """
    host, port = incomplete_cert_server
    url = f"https://{host}:{port}"
    
    # The path to the trusted leaf certificate you would generate.
    trusted_leaf_cert_path = os.path.join(os.path.dirname(__file__), "certs", "trusted-leaf-cert.pem")

    try:
        # Use your corrected adapters.py to test this request
        response = requests.get(url, verify=trusted_leaf_cert_path)
        # We expect a successful response, so the test should pass
        response.raise_for_status()
        assert response.status_code == 200
    except SSLError as e:
        # If the SSLError is raised, the test fails
        pytest.fail(f"SSLError was raised: {e}")
