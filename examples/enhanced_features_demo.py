"""
Example demonstrating the new features in requests.

This script demonstrates:
1. Middleware system
2. Enhanced timeout controls
3. Retry functionality
"""

import requests
import logging
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import sys

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('enhanced_features_demo')


# Simple HTTP server for testing
class TestHandler(BaseHTTPRequestHandler):
    # Class variables to track request counts for different endpoints
    request_counts = {
        '/delay': 0,
        '/error': 0,
    }
    
    def do_GET(self):
        """Handle GET requests with different behaviors based on the path."""
        # Log the request
        logger.info(f"Server received request for {self.path}")
        
        if self.path.startswith('/delay'):
            # Increment the request count for this path
            self.request_counts['/delay'] += 1
            count = self.request_counts['/delay']
            
            # Simulate a delay
            delay = 1 if count <= 2 else 0.1
            logger.info(f"Delaying response for {delay} seconds (request #{count})")
            time.sleep(delay)
            
            # Return success
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Response after {delay}s delay (request #{count})".encode())
            
        elif self.path.startswith('/error'):
            # Increment the request count for this path
            self.request_counts['/error'] += 1
            count = self.request_counts['/error']
            
            if count <= 2:
                # Return an error for the first 2 requests
                logger.info(f"Returning 500 for request #{count}")
                self.send_response(500)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"Internal Server Error - Please retry")
            else:
                # Return success for subsequent requests
                logger.info(f"Returning 200 for request #{count}")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"Success after retries!")
        else:
            # Default response
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Hello, this is the test server!")
    
    # Silence the default logging
    def log_message(self, format, *args):
        return


def start_test_server(port=8000):
    """Start a test HTTP server in a separate thread."""
    server = HTTPServer(('localhost', port), TestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    logger.info(f"Test server started at http://localhost:{port}")
    return server, server_thread


def test_middleware():
    """Test the middleware functionality."""
    logger.info("\n=== Testing Middleware System ===")
    
    # Reset the request counter
    TestHandler.request_counts['/delay'] = 0
    
    # Create a session with middleware
    session = requests.Session()
    
    # Add logging middleware
    session.middleware.add(requests.LoggingMiddleware(log_level=logging.INFO))
    
    # Add timing middleware
    session.middleware.add(requests.TimingMiddleware())
    
    # Add custom headers middleware
    session.middleware.add(requests.HeadersMiddleware({
        'X-Custom-Header': 'CustomValue',
        'X-Test': 'Test123'
    }))
    
    # Add custom middleware
    class CustomMiddleware(requests.Middleware):
        def process_request(self, request, context):
            logger.info("CustomMiddleware: Processing request")
            # Add a custom header
            request.headers['X-Processed-By'] = 'CustomMiddleware'
            return request
        
        def process_response(self, response, context):
            logger.info("CustomMiddleware: Processing response")
            # Add a custom attribute to the response
            response.__dict__['custom_processed'] = True
            return response
    
    session.middleware.add(CustomMiddleware())
    
    # Make a request
    try:
        response = session.get('http://localhost:8000/delay')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")
        logger.info(f"Request duration: {getattr(response, 'request_duration', 'N/A')} seconds")
        logger.info(f"Custom processed: {getattr(response, 'custom_processed', False)}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return False


def test_enhanced_timeout():
    """Test the enhanced timeout functionality."""
    logger.info("\n=== Testing Enhanced Timeout Controls ===")
    
    # Reset the request counter
    TestHandler.request_counts['/delay'] = 0
    
    # Create a session with enhanced timeout
    session = requests.Session()
    
    # Configure granular timeout
    session.default_timeout = requests.Timeout(
        connect=0.5,  # Connection timeout
        read=1.5,     # Read timeout
        write=1.0     # Write timeout
    )
    
    # Configure timeout strategy for retries
    session.timeout_strategy = requests.LinearTimeout(
        base_timeout=session.default_timeout,
        increment=0.5,  # Increase timeout by 0.5s for each retry
        max_timeout=5.0  # Maximum timeout of 5 seconds
    )
    
    # Configure retries
    session.max_retries = 3
    session.retry_on_timeout = True
    
    # Make a request that will timeout initially but succeed after retries
    try:
        response = session.get('http://localhost:8000/delay')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return False


def test_retry_with_middleware():
    """Test retry functionality with middleware."""
    logger.info("\n=== Testing Retry with Middleware ===")
    
    # Reset the request counter
    TestHandler.request_counts['/error'] = 0
    
    # Create a session with retry and middleware
    session = requests.Session()
    
    # Configure retry
    session.max_retries = 3
    session.retry_status_forcelist = {500}
    session.retry_strategy = requests.ExponentialRetryWithJitter(
        backoff_factor=0.5,
        max_backoff=5.0,
        jitter_factor=0.1
    )
    
    # Add retry context middleware to track retry attempts
    session.middleware.add(requests.RetryContextMiddleware())
    
    # Add timing middleware
    session.middleware.add(requests.TimingMiddleware())
    
    # Make a request that will fail initially but succeed after retries
    try:
        response = session.get('http://localhost:8000/error')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response body: {response.text}")
        logger.info(f"Retry count: {getattr(response, 'retry_count', 'N/A')}")
        logger.info(f"Request duration: {getattr(response, 'request_duration', 'N/A')} seconds")
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
            "Middleware System": test_middleware(),
            "Enhanced Timeout Controls": test_enhanced_timeout(),
            "Retry with Middleware": test_retry_with_middleware()
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
