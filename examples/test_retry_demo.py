"""
Test script to demonstrate the new retry functionality in requests.

This script:
1. Sets up a simple HTTP server that returns errors for the first few requests
2. Tests different retry configurations
3. Shows the results of the retries
"""

import requests
from requests.retry import ExponentialRetryWithJitter
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('retry_demo')

# Simple HTTP server that returns different status codes based on the request count
class RetryTestHandler(BaseHTTPRequestHandler):
    # Class variables to track request counts for different endpoints
    request_counts = {
        '/503': 0,  # Service Unavailable
        '/429': 0,  # Too Many Requests
        '/timeout': 0,  # Simulated timeout
        '/connection_error': 0,  # Simulated connection error
    }

    def do_GET(self):
        """Handle GET requests with different behaviors based on the path."""
        # Log the request
        logger.info(f"Server received request for {self.path}")

        if self.path in self.request_counts:
            # Increment the request count for this path
            self.request_counts[self.path] += 1
            count = self.request_counts[self.path]

            if self.path == '/503':
                # Return 503 for the first 2 requests, then 200
                if count <= 2:
                    logger.info(f"Returning 503 for request #{count} to {self.path}")
                    self.send_response(503)
                    self.send_header('Content-type', 'text/plain')
                    self.send_header('Retry-After', '1')  # Suggest retry after 1 second
                    self.end_headers()
                    self.wfile.write(b"Service Unavailable - Please retry later")
                else:
                    logger.info(f"Returning 200 for request #{count} to {self.path}")
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"Success after retries!")

            elif self.path == '/429':
                # Return 429 for the first 3 requests, then 200
                if count <= 3:
                    logger.info(f"Returning 429 for request #{count} to {self.path}")
                    self.send_response(429)
                    self.send_header('Content-type', 'text/plain')
                    self.send_header('Retry-After', '2')  # Suggest retry after 2 seconds
                    self.end_headers()
                    self.wfile.write(b"Too Many Requests - Please retry later")
                else:
                    logger.info(f"Returning 200 for request #{count} to {self.path}")
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"Success after retries!")

            elif self.path == '/timeout':
                # Simulate timeout for the first 2 requests, then respond normally
                if count <= 2:
                    logger.info(f"Simulating timeout for request #{count} to {self.path}")
                    time.sleep(3)  # Sleep to simulate timeout (client should timeout before this)
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"This response would timeout if client timeout is < 3 seconds")
                else:
                    logger.info(f"Returning 200 for request #{count} to {self.path}")
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"Success after retries!")

            elif self.path == '/connection_error':
                # Simulate connection error for the first 2 requests by closing the connection
                if count <= 2:
                    logger.info(f"Simulating connection error for request #{count} to {self.path}")
                    self.wfile.close()  # Close the connection without sending a response
                else:
                    logger.info(f"Returning 200 for request #{count} to {self.path}")
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"Success after retries!")
        else:
            # Default response for other paths
            logger.info(f"Returning 200 for request to {self.path}")
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Hello, this is the test server!")

    # Silence the default logging
    def log_message(self, format, *args):
        return


def start_test_server(port=8000):
    """Start a test HTTP server in a separate thread."""
    server = HTTPServer(('localhost', port), RetryTestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    logger.info(f"Test server started at http://localhost:{port}")
    return server, server_thread


def test_basic_retry():
    """Test basic retry functionality with 503 errors."""
    logger.info("\n=== Testing basic retry with 503 errors ===")

    # Reset the request counter
    RetryTestHandler.request_counts['/503'] = 0

    # Create a session with retry
    session = requests.Session()
    session.max_retries = 3  # Maximum number of retries
    session.retry_status_forcelist = {503}  # Retry on 503 Service Unavailable

    try:
        # This should succeed after 2 retries (3 requests total)
        start_time = time.time()
        response = session.get('http://localhost:8000/503', timeout=1)
        elapsed = time.time() - start_time

        logger.info(f"Request succeeded after {RetryTestHandler.request_counts['/503']} attempts")
        logger.info(f"Total time: {elapsed:.2f} seconds")
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return False


def test_retry_with_custom_strategy():
    """Test retry with a custom exponential backoff strategy."""
    logger.info("\n=== Testing retry with custom exponential backoff strategy ===")

    # Reset the request counter
    RetryTestHandler.request_counts['/429'] = 0

    # Create a session with custom retry strategy
    session = requests.Session()
    session.max_retries = 5  # Maximum number of retries
    session.retry_strategy = ExponentialRetryWithJitter(
        backoff_factor=0.5,  # Start with 0.5 second delay
        max_backoff=10,      # Maximum backoff of 10 seconds
        jitter_factor=0.1    # Add 10% jitter
    )
    session.retry_status_forcelist = {429}  # Retry on 429 Too Many Requests

    try:
        # This should succeed after 3 retries (4 requests total)
        start_time = time.time()
        response = session.get('http://localhost:8000/429', timeout=2)
        elapsed = time.time() - start_time

        logger.info(f"Request succeeded after {RetryTestHandler.request_counts['/429']} attempts")
        logger.info(f"Total time: {elapsed:.2f} seconds")
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return False


def test_retry_on_timeout():
    """Test retry on timeout errors."""
    logger.info("\n=== Testing retry on timeout errors ===")

    # Reset the request counter
    RetryTestHandler.request_counts['/timeout'] = 0

    # Create a session with retry on timeout
    session = requests.Session()
    session.max_retries = 3  # Maximum number of retries
    session.retry_on_timeout = True  # Retry on timeout errors

    try:
        # This should succeed after 2 retries (3 requests total)
        start_time = time.time()
        response = session.get('http://localhost:8000/timeout', timeout=1)
        elapsed = time.time() - start_time

        logger.info(f"Request succeeded after {RetryTestHandler.request_counts['/timeout']} attempts")
        logger.info(f"Total time: {elapsed:.2f} seconds")
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return False


def test_retry_on_connection_error():
    """Test retry on connection errors."""
    logger.info("\n=== Testing retry on connection errors ===")

    # Reset the request counter
    RetryTestHandler.request_counts['/connection_error'] = 0

    # Create a session with retry on connection errors
    session = requests.Session()
    session.max_retries = 3  # Maximum number of retries
    session.retry_on_connection_error = True  # Retry on connection errors

    try:
        # This should succeed after 2 retries (3 requests total)
        start_time = time.time()
        response = session.get('http://localhost:8000/connection_error', timeout=1)
        elapsed = time.time() - start_time

        logger.info(f"Request succeeded after {RetryTestHandler.request_counts['/connection_error']} attempts")
        logger.info(f"Total time: {elapsed:.2f} seconds")
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return False


def main():
    """Run all the tests."""
    # Start the test server
    server, thread = start_test_server()

    try:
        # Wait a moment for the server to start
        time.sleep(1)

        # Run the tests
        results = {
            "Basic Retry": test_basic_retry(),
            "Custom Strategy": test_retry_with_custom_strategy(),
            "Retry on Timeout": test_retry_on_timeout(),
            "Retry on Connection Error": test_retry_on_connection_error()
        }

        # Print summary
        logger.info("\n=== Test Results Summary ===")
        for test_name, success in results.items():
            logger.info(f"{test_name}: {'SUCCESS' if success else 'FAILED'}")

    finally:
        # Shutdown the server
        server.shutdown()
        logger.info("Test server stopped")


if __name__ == "__main__":
    main()
