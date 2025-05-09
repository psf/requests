"""
requests.middleware
~~~~~~~~~~~~~~~~~

This module provides middleware functionality for the requests library.
Middleware allows for custom processing of requests and responses.
"""

from typing import Callable, Dict, List, Optional, Union, Any, TypeVar
import logging

# Type definitions
RequestType = TypeVar('RequestType')
ResponseType = TypeVar('ResponseType')
MiddlewareFunc = Callable[[RequestType, Dict[str, Any]], RequestType]
ResponseMiddlewareFunc = Callable[[ResponseType, Dict[str, Any]], ResponseType]

logger = logging.getLogger(__name__)


class Middleware:
    """Base class for all middleware."""
    
    def __init__(self, name: Optional[str] = None):
        """
        Initialize a middleware.
        
        :param name: Optional name for the middleware
        """
        self.name = name or self.__class__.__name__
    
    def process_request(self, request: RequestType, context: Dict[str, Any]) -> RequestType:
        """
        Process a request before it is sent.
        
        :param request: The request object
        :param context: A dictionary containing context information
        :return: The processed request
        """
        return request
    
    def process_response(self, response: ResponseType, context: Dict[str, Any]) -> ResponseType:
        """
        Process a response after it is received.
        
        :param response: The response object
        :param context: A dictionary containing context information
        :return: The processed response
        """
        return response
    
    def __str__(self) -> str:
        return f"{self.name}"


class MiddlewareChain:
    """A chain of middleware to be applied to requests and responses."""
    
    def __init__(self):
        """Initialize an empty middleware chain."""
        self.middleware: List[Middleware] = []
    
    def add(self, middleware: Middleware) -> 'MiddlewareChain':
        """
        Add a middleware to the chain.
        
        :param middleware: The middleware to add
        :return: The middleware chain for chaining
        """
        self.middleware.append(middleware)
        return self
    
    def remove(self, middleware_name: str) -> bool:
        """
        Remove a middleware from the chain by name.
        
        :param middleware_name: The name of the middleware to remove
        :return: True if the middleware was removed, False otherwise
        """
        for i, middleware in enumerate(self.middleware):
            if middleware.name == middleware_name:
                self.middleware.pop(i)
                return True
        return False
    
    def clear(self) -> None:
        """Clear all middleware from the chain."""
        self.middleware.clear()
    
    def process_request(self, request: RequestType, context: Optional[Dict[str, Any]] = None) -> RequestType:
        """
        Process a request through all middleware in the chain.
        
        :param request: The request object
        :param context: Optional context dictionary
        :return: The processed request
        """
        ctx = context or {}
        processed_request = request
        
        for middleware in self.middleware:
            try:
                processed_request = middleware.process_request(processed_request, ctx)
            except Exception as e:
                logger.error(f"Error in middleware {middleware}: {e}")
                # Continue with the original request if middleware fails
                
        return processed_request
    
    def process_response(self, response: ResponseType, context: Optional[Dict[str, Any]] = None) -> ResponseType:
        """
        Process a response through all middleware in the chain in reverse order.
        
        :param response: The response object
        :param context: Optional context dictionary
        :return: The processed response
        """
        ctx = context or {}
        processed_response = response
        
        # Process response middleware in reverse order
        for middleware in reversed(self.middleware):
            try:
                processed_response = middleware.process_response(processed_response, ctx)
            except Exception as e:
                logger.error(f"Error in middleware {middleware}: {e}")
                # Continue with the original response if middleware fails
                
        return processed_response
    
    def __len__(self) -> int:
        return len(self.middleware)


# Common middleware implementations

class LoggingMiddleware(Middleware):
    """Middleware for logging requests and responses."""
    
    def __init__(self, name: Optional[str] = None, log_level: int = logging.INFO):
        """
        Initialize a logging middleware.
        
        :param name: Optional name for the middleware
        :param log_level: The logging level to use
        """
        super().__init__(name)
        self.log_level = log_level
        self.logger = logging.getLogger(f"requests.middleware.{self.name}")
    
    def process_request(self, request: RequestType, context: Dict[str, Any]) -> RequestType:
        """Log the request."""
        self.logger.log(self.log_level, f"Request: {request.method} {request.url}")
        if hasattr(request, 'headers') and request.headers:
            self.logger.log(self.log_level, f"Headers: {request.headers}")
        return request
    
    def process_response(self, response: ResponseType, context: Dict[str, Any]) -> ResponseType:
        """Log the response."""
        if hasattr(response, 'status_code') and hasattr(response, 'url'):
            self.logger.log(self.log_level, f"Response: {response.status_code} from {response.url}")
        if hasattr(response, 'headers') and response.headers:
            self.logger.log(self.log_level, f"Headers: {response.headers}")
        return response


class TimingMiddleware(Middleware):
    """Middleware for timing requests and responses."""
    
    def process_request(self, request: RequestType, context: Dict[str, Any]) -> RequestType:
        """Record the start time of the request."""
        import time
        context['request_start_time'] = time.time()
        return request
    
    def process_response(self, response: ResponseType, context: Dict[str, Any]) -> ResponseType:
        """Calculate and log the request duration."""
        import time
        if 'request_start_time' in context:
            duration = time.time() - context['request_start_time']
            logger.info(f"Request took {duration:.2f} seconds")
            # Add the duration to the response object for later use
            if hasattr(response, '__dict__'):
                response.__dict__['request_duration'] = duration
        return response


class HeadersMiddleware(Middleware):
    """Middleware for adding headers to requests."""
    
    def __init__(self, headers: Dict[str, str], name: Optional[str] = None):
        """
        Initialize a headers middleware.
        
        :param headers: Dictionary of headers to add to requests
        :param name: Optional name for the middleware
        """
        super().__init__(name)
        self.headers = headers
    
    def process_request(self, request: RequestType, context: Dict[str, Any]) -> RequestType:
        """Add headers to the request."""
        if hasattr(request, 'headers'):
            for key, value in self.headers.items():
                request.headers[key] = value
        return request


class UserAgentMiddleware(HeadersMiddleware):
    """Middleware for setting a custom User-Agent header."""
    
    def __init__(self, user_agent: str, name: Optional[str] = None):
        """
        Initialize a User-Agent middleware.
        
        :param user_agent: The User-Agent string to use
        :param name: Optional name for the middleware
        """
        super().__init__({"User-Agent": user_agent}, name)


class AuthMiddleware(Middleware):
    """Middleware for adding authentication to requests."""
    
    def __init__(self, auth_func: Callable[[RequestType], RequestType], name: Optional[str] = None):
        """
        Initialize an authentication middleware.
        
        :param auth_func: Function that adds authentication to a request
        :param name: Optional name for the middleware
        """
        super().__init__(name)
        self.auth_func = auth_func
    
    def process_request(self, request: RequestType, context: Dict[str, Any]) -> RequestType:
        """Apply authentication to the request."""
        return self.auth_func(request)


class RetryContextMiddleware(Middleware):
    """Middleware for tracking retry attempts."""
    
    def process_request(self, request: RequestType, context: Dict[str, Any]) -> RequestType:
        """Track retry attempts in the context."""
        if 'retry_count' not in context:
            context['retry_count'] = 0
        else:
            context['retry_count'] += 1
        
        if hasattr(request, '__dict__'):
            request.__dict__['retry_count'] = context['retry_count']
        
        return request
    
    def process_response(self, response: ResponseType, context: Dict[str, Any]) -> ResponseType:
        """Add retry information to the response."""
        if 'retry_count' in context and hasattr(response, '__dict__'):
            response.__dict__['retry_count'] = context['retry_count']
        return response
