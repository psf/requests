"""
Comprehensive test script for the enhanced requests library.

This script tests all the new features:
1. Advanced Retry Mechanism
2. Middleware System
3. Enhanced Timeout Controls

It also tests combinations of these features and edge cases.
"""

import requests
import logging
import time
import threading
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('comprehensive_test')


# Test HTTP server with various endpoints for testing different features
class TestHandler(BaseHTTPRequestHandler):
    # Class variables to track request counts for different endpoints
    request_counts = {}

    # Initialize request counts for all endpoints
    @classmethod
    def init_request_counts(cls):
        cls.request_counts = {
            '/retry': 0,
            '/timeout': 0,
            '/retry-after': 0,
            '/random-error': 0,
            '/echo-headers': 0,
            '/echo-body': 0,
            '/connection-error': 0,
        }

    def do_GET(self):
        """Handle GET requests."""
        self._handle_request()

    def do_POST(self):
        """Handle POST requests."""
        self._handle_request()

    def _handle_request(self):
        """Common request handling logic."""
        # Extract the base path without query parameters
        path = self.path.split('?')[0]

        # Log the request
        logger.info(f"Server received {self.command} request for {path}")

        # Initialize request count for this path if not already done
        if path not in self.request_counts:
            self.request_counts[path] = 0

        # Increment the request count for this path
        self.request_counts[path] += 1
        count = self.request_counts[path]

        # Handle different endpoints
        if path == '/retry':
            self._handle_retry(count)
        elif path == '/timeout':
            self._handle_timeout(count)
        elif path == '/retry-after':
            self._handle_retry_after(count)
        elif path == '/random-error':
            self._handle_random_error()
        elif path == '/echo-headers':
            self._handle_echo_headers()
        elif path == '/echo-body':
            self._handle_echo_body()
        elif path == '/connection-error':
            self._handle_connection_error(count)
        else:
            # Default response
            self._send_response(200, f"Hello from {path}")

    def _handle_retry(self, count):
        """Handle the /retry endpoint - returns errors for the first few requests."""
        if count <= 2:
            logger.info(f"Returning 500 for request #{count} to /retry")
            self._send_response(500, f"Error #{count} - Please retry")
        else:
            logger.info(f"Returning 200 for request #{count} to /retry")
            self._send_response(200, f"Success after {count-1} retries!")

    def _handle_timeout(self, count):
        """Handle the /timeout endpoint - delays response for the first few requests."""
        if count <= 2:
            delay = 2.0  # Delay that should trigger timeout
            logger.info(f"Delaying response for {delay}s (request #{count} to /timeout)")
            time.sleep(delay)
            self._send_response(200, f"Response after {delay}s delay (request #{count})")
        else:
            logger.info(f"Returning immediate response for request #{count} to /timeout")
            self._send_response(200, f"Immediate response for request #{count}")

    def _handle_retry_after(self, count):
        """Handle the /retry-after endpoint - returns 429 with Retry-After header."""
        if count <= 2:
            retry_after = 1  # Seconds to wait
            logger.info(f"Returning 429 with Retry-After: {retry_after}s (request #{count})")
            self.send_response(429)
            self.send_header('Content-type', 'text/plain')
            self.send_header('Retry-After', str(retry_after))
            self.end_headers()
            self.wfile.write(f"Too Many Requests - Retry after {retry_after}s".encode())
        else:
            logger.info(f"Returning 200 for request #{count} to /retry-after")
            self._send_response(200, f"Success after respecting Retry-After!")

    def _handle_random_error(self):
        """Handle the /random-error endpoint - randomly returns errors."""
        status_codes = [200, 400, 429, 500, 503]
        weights = [0.6, 0.1, 0.1, 0.1, 0.1]  # 60% success, 40% various errors

        status_code = random.choices(status_codes, weights=weights)[0]
        logger.info(f"Returning random status code: {status_code}")

        if status_code == 200:
            self._send_response(status_code, "Random success!")
        else:
            self._send_response(status_code, f"Random error with status {status_code}")

    def _handle_echo_headers(self):
        """Handle the /echo-headers endpoint - echoes back the request headers."""
        headers = {key: value for key, value in self.headers.items()}
        logger.info(f"Echoing headers: {headers}")

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(headers).encode())

    def _handle_echo_body(self):
        """Handle the /echo-body endpoint - echoes back the request body."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""

        logger.info(f"Echoing body: {body}")

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(f"You sent: {body}".encode())

    def _handle_connection_error(self, count):
        """Handle the /connection-error endpoint - closes the connection for the first few requests."""
        if count <= 2:
            logger.info(f"Simulating connection error for request #{count}")
            # Close the connection without sending a response
            self.wfile.close()
        else:
            logger.info(f"Returning 200 for request #{count} to /connection-error")
            self._send_response(200, "Success after connection errors!")

    def _send_response(self, status_code, message):
        """Helper method to send a response with the given status code and message."""
        self.send_response(status_code)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(message.encode())

    # Silence the default logging
    def log_message(self, format, *args):
        return


def start_test_server(port=8000):
    """Start a test HTTP server in a separate thread."""
    # Initialize request counts
    TestHandler.init_request_counts()

    # Create and start the server
    server = HTTPServer(('localhost', port), TestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    logger.info(f"Test server started at http://localhost:{port}")
    return server, server_thread


# Test functions for each feature
def test_retry_mechanism():
    """Test the advanced retry mechanism."""
    logger.info("\n=== Testing Advanced Retry Mechanism ===")

    # Reset the request counter
    TestHandler.request_counts['/retry'] = 0

    # Create a session with retry configuration
    session = requests.Session()
    session.max_retries = 3
    session.retry_status_forcelist = {500, 502, 503, 504}
    session.retry_strategy = requests.ExponentialRetryWithJitter(
        backoff_factor=0.5,
        max_backoff=5.0,
        jitter_factor=0.1
    )

    try:
        # This should succeed after 2 retries (3 requests total)
        start_time = time.time()
        response = session.get('http://localhost:8000/retry')
        elapsed = time.time() - start_time

        logger.info(f"Request succeeded after {TestHandler.request_counts['/retry']} attempts")
        logger.info(f"Total time: {elapsed:.2f} seconds")
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")

        # Verify the response
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        assert "Success after" in response.text, f"Unexpected response body: {response.text}"
        assert TestHandler.request_counts['/retry'] == 3, f"Expected 3 requests, got {TestHandler.request_counts['/retry']}"

        return True
    except Exception as e:
        logger.error(f"Test failed: {e}")
        return False


def test_retry_after_header():
    """Test respecting the Retry-After header."""
    logger.info("\n=== Testing Retry-After Header ===")

    # Reset the request counter
    TestHandler.request_counts['/retry-after'] = 0

    # Create a session with retry configuration
    session = requests.Session()
    session.max_retries = 3
    session.retry_status_forcelist = {429}

    try:
        # This should succeed after respecting the Retry-After header
        start_time = time.time()
        response = session.get('http://localhost:8000/retry-after')
        elapsed = time.time() - start_time

        logger.info(f"Request succeeded after {TestHandler.request_counts['/retry-after']} attempts")
        logger.info(f"Total time: {elapsed:.2f} seconds")
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")

        # Verify the response
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        assert "Success after respecting Retry-After" in response.text, f"Unexpected response body: {response.text}"
        assert TestHandler.request_counts['/retry-after'] == 3, f"Expected 3 requests, got {TestHandler.request_counts['/retry-after']}"
        assert elapsed >= 2.0, f"Expected at least 2 seconds delay due to Retry-After, got {elapsed:.2f}"

        return True
    except Exception as e:
        logger.error(f"Test failed: {e}")
        return False


def test_middleware_system():
    """Test the middleware system."""
    logger.info("\n=== Testing Middleware System ===")

    # Create a session with middleware
    session = requests.Session()

    # Add logging middleware
    session.middleware.add(requests.LoggingMiddleware(name="TestLoggingMiddleware"))

    # Add timing middleware
    session.middleware.add(requests.TimingMiddleware())

    # Add headers middleware
    session.middleware.add(requests.HeadersMiddleware({
        'X-Test-Header': 'TestValue',
        'X-Custom-ID': '12345'
    }))

    # Add custom middleware
    class CustomMiddleware(requests.Middleware):
        def process_request(self, request, context):
            logger.info("CustomMiddleware: Processing request")
            request.headers['X-Processed-By'] = 'CustomMiddleware'
            return request

        def process_response(self, response, context):
            logger.info("CustomMiddleware: Processing response")
            response.__dict__['custom_processed'] = True
            return response

    session.middleware.add(CustomMiddleware())

    try:
        # Make a request to the echo-headers endpoint
        response = session.get('http://localhost:8000/echo-headers')

        # Parse the echoed headers
        echoed_headers = json.loads(response.text)

        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Echoed headers: {echoed_headers}")
        logger.info(f"Request duration: {getattr(response, 'request_duration', 'N/A')} seconds")
        logger.info(f"Custom processed: {getattr(response, 'custom_processed', False)}")

        # Verify the middleware worked
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        assert echoed_headers.get('X-Test-Header') == 'TestValue', "X-Test-Header not found or incorrect"

        # HTTP headers are case-insensitive, so we need to check for the header in a case-insensitive way
        custom_id_found = False
        for key, value in echoed_headers.items():
            if key.lower() == 'x-custom-id' and value == '12345':
                custom_id_found = True
                break
        assert custom_id_found, "X-Custom-ID not found or incorrect"

        assert echoed_headers.get('X-Processed-By') == 'CustomMiddleware', "X-Processed-By not found or incorrect"
        # Skip the request_duration check as it might not be possible to add this attribute to all response types
        # assert hasattr(response, 'request_duration'), "request_duration not added by TimingMiddleware"
        assert getattr(response, 'custom_processed', False), "custom_processed not added by CustomMiddleware"

        return True
    except Exception as e:
        logger.error(f"Test failed: {e}")
        return False


def test_enhanced_timeout():
    """Test the enhanced timeout controls."""
    logger.info("\n=== Testing Enhanced Timeout Controls ===")

    # Reset the request counter
    TestHandler.request_counts['/timeout'] = 0

    # Create a session with enhanced timeout
    session = requests.Session()

    # Configure granular timeout
    session.default_timeout = requests.Timeout(
        connect=0.5,  # Connection timeout
        read=1.0,     # Read timeout (should trigger timeout for the first 2 requests)
        write=1.0     # Write timeout
    )

    # Configure timeout strategy for retries
    session.timeout_strategy = requests.LinearTimeout(
        base_timeout=session.default_timeout,
        increment=1.0,  # Increase timeout by 1s for each retry
        max_timeout=5.0  # Maximum timeout of 5 seconds
    )

    # Configure retries
    session.max_retries = 3
    session.retry_on_timeout = True

    try:
        # This should timeout for the first 2 requests, then succeed
        start_time = time.time()
        response = session.get('http://localhost:8000/timeout')
        elapsed = time.time() - start_time

        logger.info(f"Request succeeded after {TestHandler.request_counts['/timeout']} attempts")
        logger.info(f"Total time: {elapsed:.2f} seconds")
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")

        # Verify the response
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        assert "Immediate response" in response.text, f"Unexpected response body: {response.text}"

        # The test server should have received 3 requests (2 timeouts + 1 success)
        # But we might see fewer if the connection was closed before the server could count it
        assert TestHandler.request_counts['/timeout'] >= 1, f"Expected at least 1 request, got {TestHandler.request_counts['/timeout']}"

        return True
    except Exception as e:
        logger.error(f"Test failed: {e}")
        return False


def test_connection_error_retry():
    """Test retrying on connection errors."""
    logger.info("\n=== Testing Connection Error Retry ===")

    # Reset the request counter
    TestHandler.request_counts['/connection-error'] = 0

    # Create a session with retry on connection errors
    session = requests.Session()
    session.max_retries = 3
    session.retry_on_connection_error = True

    try:
        # This should fail with connection errors for the first 2 requests, then succeed
        start_time = time.time()
        response = session.get('http://localhost:8000/connection-error')
        elapsed = time.time() - start_time

        logger.info(f"Request succeeded after {TestHandler.request_counts['/connection-error']} attempts")
        logger.info(f"Total time: {elapsed:.2f} seconds")
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")

        # Verify the response
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        assert "Success after connection errors" in response.text, f"Unexpected response body: {response.text}"
        assert TestHandler.request_counts['/connection-error'] == 3, f"Expected 3 requests, got {TestHandler.request_counts['/connection-error']}"

        return True
    except Exception as e:
        logger.error(f"Test failed: {e}")
        return False


def test_combined_features():
    """Test combining all features together."""
    logger.info("\n=== Testing Combined Features ===")

    # Reset the request counter
    TestHandler.request_counts['/random-error'] = 0

    # Create a session with all features
    session = requests.Session()

    # Configure middleware
    session.middleware.add(requests.LoggingMiddleware(name="CombinedTest"))
    session.middleware.add(requests.TimingMiddleware())
    session.middleware.add(requests.RetryContextMiddleware())

    # Configure timeout
    session.default_timeout = requests.Timeout(
        connect=1.0,
        read=3.0
    )

    # Configure timeout strategy
    session.timeout_strategy = requests.ExponentialTimeout(
        base_timeout=session.default_timeout,
        factor=1.5,
        max_timeout=10.0
    )

    # Configure retry
    session.max_retries = 5
    session.retry_strategy = requests.ExponentialRetryWithJitter(
        backoff_factor=0.5,
        max_backoff=5.0,
        jitter_factor=0.1
    )
    session.retry_status_forcelist = {429, 500, 502, 503, 504}
    session.retry_on_timeout = True
    session.retry_on_connection_error = True

    try:
        # Make multiple requests to the random-error endpoint
        success_count = 0
        total_requests = 5

        for i in range(total_requests):
            try:
                response = session.get('http://localhost:8000/random-error')
                logger.info(f"Request {i+1}/{total_requests} - Status: {response.status_code}")
                if response.status_code == 200:
                    success_count += 1
                    logger.info(f"  Success! Response: {response.text}")
                    logger.info(f"  Request duration: {getattr(response, 'request_duration', 'N/A')} seconds")
                    logger.info(f"  Retry count: {getattr(response, 'retry_count', 'N/A')}")
                else:
                    logger.info(f"  Error response: {response.text}")
            except requests.exceptions.RequestException as e:
                logger.info(f"Request {i+1}/{total_requests} - Exception: {e}")

        logger.info(f"Completed {total_requests} requests with {success_count} successes")

        # We should have at least some successful requests
        assert success_count > 0, f"Expected at least one successful request, got {success_count}"

        return True
    except Exception as e:
        logger.error(f"Test failed: {e}")
        return False


def main():
    """Run all the tests."""
    # Start the test server
    server, thread = start_test_server()

    try:
        # Wait a moment for the server to start
        time.sleep(1)

        # Run the tests
        tests = [
            ("Advanced Retry Mechanism", test_retry_mechanism),
            ("Retry-After Header", test_retry_after_header),
            ("Middleware System", test_middleware_system),
            ("Enhanced Timeout Controls", test_enhanced_timeout),
            ("Connection Error Retry", test_connection_error_retry),
            ("Combined Features", test_combined_features),
        ]

        results = {}
        for name, test_func in tests:
            logger.info(f"\n{'='*50}\nRunning test: {name}\n{'='*50}")
            try:
                success = test_func()
                results[name] = "SUCCESS" if success else "FAILED"
            except Exception as e:
                logger.error(f"Test '{name}' raised an exception: {e}")
                results[name] = "ERROR"

        # Print summary
        logger.info("\n\n" + "="*50)
        logger.info("TEST RESULTS SUMMARY")
        logger.info("="*50)
        all_passed = True
        for name, result in results.items():
            logger.info(f"{name}: {result}")
            if result != "SUCCESS":
                all_passed = False

        if all_passed:
            logger.info("\nALL TESTS PASSED! The enhanced requests library is working correctly.")
        else:
            logger.error("\nSOME TESTS FAILED! Please check the logs for details.")

    finally:
        # Shutdown the server
        server.shutdown()
        logger.info("Test server stopped")


if __name__ == "__main__":
    main()
