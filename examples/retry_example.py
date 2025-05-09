"""
Example demonstrating the new retry functionality in requests.
"""

import requests
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import sys

# Simple HTTP server that returns different status codes based on the number of requests
class RetryTestHandler(BaseHTTPRequestHandler):
    # Class variable to track request count
    request_count = 0
    
    def do_GET(self):
        # Increment the request count
        RetryTestHandler.request_count += 1
        
        # Log the request
        print(f"Request #{RetryTestHandler.request_count} received")
        
        # Return different status codes based on the request count
        if RetryTestHandler.request_count <= 2:
            # First two requests will fail with 503 Service Unavailable
            self.send_response(503)
            self.send_header('Content-type', 'text/plain')
            self.send_header('Retry-After', '1')  # Suggest retry after 1 second
            self.end_headers()
            self.wfile.write(b"Service Unavailable - Please retry later")
            print("Responded with 503 Service Unavailable")
        else:
            # Third request will succeed with 200 OK
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Success! The request was retried and succeeded.")
            print("Responded with 200 OK")
    
    # Silence the default logging
    def log_message(self, format, *args):
        return


def start_test_server(port=8000):
    """Start a test HTTP server in a separate thread."""
    server = HTTPServer(('localhost', port), RetryTestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server, server_thread


def example_without_retry():
    """Example without retry functionality."""
    print("\n=== Example without retry ===")
    
    # Reset the request counter
    RetryTestHandler.request_count = 0
    
    try:
        # Create a session without retry
        session = requests.Session()
        
        # Make a request that will fail
        response = session.get('http://localhost:8000')
        
        # This will not be reached for the first request
        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.text}")
        
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")


def example_with_retry():
    """Example with the new retry functionality."""
    print("\n=== Example with retry ===")
    
    # Reset the request counter
    RetryTestHandler.request_count = 0
    
    # Create a session with retry
    session = requests.Session()
    
    # Configure retry settings
    session.max_retries = 3  # Maximum number of retries
    session.retry_status_forcelist = {503}  # Retry on 503 Service Unavailable
    session.retry_on_timeout = True  # Retry on timeout errors
    
    # Make a request that will initially fail but eventually succeed after retries
    try:
        response = session.get('http://localhost:8000')
        print(f"Final response status: {response.status_code}")
        print(f"Final response body: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"All retries failed: {e}")


def example_with_custom_retry_strategy():
    """Example with a custom retry strategy."""
    print("\n=== Example with custom retry strategy ===")
    
    # Reset the request counter
    RetryTestHandler.request_count = 0
    
    # Create a session with custom retry strategy
    session = requests.Session()
    
    # Configure retry settings with exponential backoff
    session.max_retries = 5  # Maximum number of retries
    session.retry_strategy = requests.ExponentialRetryWithJitter(
        backoff_factor=0.5,  # Start with 0.5 second delay
        max_backoff=10,      # Maximum backoff of 10 seconds
        jitter_factor=0.1    # Add 10% jitter to avoid thundering herd
    )
    session.retry_status_forcelist = {500, 502, 503, 504}  # Common server errors
    
    # Make a request that will initially fail but eventually succeed after retries
    try:
        response = session.get('http://localhost:8000')
        print(f"Final response status: {response.status_code}")
        print(f"Final response body: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"All retries failed: {e}")


def main():
    # Start the test server
    server, thread = start_test_server()
    print("Test server started at http://localhost:8000")
    
    try:
        # Wait a moment for the server to start
        time.sleep(1)
        
        # Run the examples
        example_without_retry()
        example_with_retry()
        example_with_custom_retry_strategy()
        
    finally:
        # Shutdown the server
        server.shutdown()
        print("\nTest server stopped")


if __name__ == "__main__":
    main()
