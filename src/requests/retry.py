"""
requests.retry
~~~~~~~~~~~~~

This module provides retry functionality for the requests library.
"""

import random
import time
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

from urllib3.util import Retry as Urllib3Retry

# Status codes that should trigger a retry by default
DEFAULT_RETRY_STATUS_CODES = frozenset([413, 429, 500, 502, 503, 504])

# HTTP methods that should be retried by default
DEFAULT_RETRY_METHODS = frozenset(['GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'])


class RetryStrategy:
    """Base class for retry strategies."""
    
    def get_backoff_time(self, retry_number: int) -> float:
        """
        Get the backoff time for the current retry attempt.
        
        :param retry_number: The current retry attempt (0-based)
        :return: Time to wait in seconds
        """
        raise NotImplementedError("Retry strategies must implement get_backoff_time")


class ConstantRetry(RetryStrategy):
    """Retry with a constant delay between attempts."""
    
    def __init__(self, backoff_factor: float = 1.0):
        """
        Initialize a constant retry strategy.
        
        :param backoff_factor: The constant time to wait between retries in seconds
        """
        self.backoff_factor = backoff_factor
    
    def get_backoff_time(self, retry_number: int) -> float:
        """
        Get the constant backoff time.
        
        :param retry_number: The current retry attempt (0-based)
        :return: Time to wait in seconds
        """
        return self.backoff_factor


class ExponentialRetry(RetryStrategy):
    """Retry with exponential backoff between attempts."""
    
    def __init__(self, backoff_factor: float = 0.5, max_backoff: float = 120):
        """
        Initialize an exponential retry strategy.
        
        :param backoff_factor: The base backoff factor in seconds
        :param max_backoff: Maximum backoff time in seconds
        """
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
    
    def get_backoff_time(self, retry_number: int) -> float:
        """
        Get the exponential backoff time.
        
        :param retry_number: The current retry attempt (0-based)
        :return: Time to wait in seconds
        """
        # {backoff factor} * (2 ^ (retry_number))
        backoff = self.backoff_factor * (2 ** retry_number)
        return min(backoff, self.max_backoff)


class ExponentialRetryWithJitter(ExponentialRetry):
    """Retry with exponential backoff and jitter between attempts."""
    
    def __init__(self, backoff_factor: float = 0.5, max_backoff: float = 120, jitter_factor: float = 0.2):
        """
        Initialize an exponential retry strategy with jitter.
        
        :param backoff_factor: The base backoff factor in seconds
        :param max_backoff: Maximum backoff time in seconds
        :param jitter_factor: The jitter factor (0-1) to apply to the backoff time
        """
        super().__init__(backoff_factor, max_backoff)
        self.jitter_factor = jitter_factor
    
    def get_backoff_time(self, retry_number: int) -> float:
        """
        Get the exponential backoff time with jitter.
        
        :param retry_number: The current retry attempt (0-based)
        :return: Time to wait in seconds with jitter applied
        """
        backoff = super().get_backoff_time(retry_number)
        jitter = backoff * self.jitter_factor
        return backoff + random.uniform(-jitter, jitter)


class Retry:
    """
    Retry configuration for requests.
    
    This class provides a more flexible and powerful retry mechanism than the
    default urllib3 Retry class, with support for different backoff strategies,
    custom retry conditions, and more.
    """
    
    def __init__(
        self,
        total: int = 3,
        status_forcelist: Optional[Set[int]] = None,
        allowed_methods: Optional[Set[str]] = None,
        backoff_strategy: Optional[RetryStrategy] = None,
        respect_retry_after_header: bool = True,
        retry_on_timeout: bool = False,
        retry_on_connection_error: bool = True,
        raise_on_status: bool = True,
        raise_on_redirect: bool = True,
        history: Optional[List[Dict]] = None
    ):
        """
        Initialize a Retry object.
        
        :param total: Total number of retries to allow
        :param status_forcelist: A set of status codes that should force a retry
        :param allowed_methods: A set of HTTP methods to retry
        :param backoff_strategy: The backoff strategy to use
        :param respect_retry_after_header: Whether to respect Retry-After headers
        :param retry_on_timeout: Whether to retry on timeout errors
        :param retry_on_connection_error: Whether to retry on connection errors
        :param raise_on_status: Whether to raise an exception on bad status codes
        :param raise_on_redirect: Whether to raise an exception on redirect limit
        :param history: History of previous retry attempts
        """
        self.total = total
        self.status_forcelist = status_forcelist or DEFAULT_RETRY_STATUS_CODES
        self.allowed_methods = allowed_methods or DEFAULT_RETRY_METHODS
        self.backoff_strategy = backoff_strategy or ExponentialRetryWithJitter()
        self.respect_retry_after_header = respect_retry_after_header
        self.retry_on_timeout = retry_on_timeout
        self.retry_on_connection_error = retry_on_connection_error
        self.raise_on_status = raise_on_status
        self.raise_on_redirect = raise_on_redirect
        self.history = history or []
    
    def to_urllib3_retry(self) -> Urllib3Retry:
        """
        Convert this Retry object to a urllib3 Retry object.
        
        :return: A urllib3 Retry object with equivalent settings
        """
        return Urllib3Retry(
            total=self.total,
            status_forcelist=self.status_forcelist,
            allowed_methods=self.allowed_methods,
            backoff_factor=0.5,  # We'll handle our own backoff
            respect_retry_after_header=self.respect_retry_after_header,
            raise_on_status=self.raise_on_status,
            raise_on_redirect=self.raise_on_redirect
        )
    
    def get_backoff_time(self, retry_number: int) -> float:
        """
        Get the backoff time for the current retry attempt.
        
        :param retry_number: The current retry attempt (0-based)
        :return: Time to wait in seconds
        """
        return self.backoff_strategy.get_backoff_time(retry_number)
    
    def increment(
        self,
        method: Optional[str] = None,
        url: Optional[str] = None,
        response: Optional[object] = None,
        error: Optional[Exception] = None,
        _pool: Optional[object] = None,
        _stacktrace: Optional[object] = None
    ) -> 'Retry':
        """
        Return a new Retry object with incremented retry counter.
        
        :param method: The HTTP method used in the request
        :param url: The URL that was requested
        :param response: The response object (if one was received)
        :param error: The error that occurred (if any)
        :param _pool: The connection pool (passed through to urllib3)
        :param _stacktrace: The stacktrace (passed through to urllib3)
        :return: A new Retry object with updated retry count and history
        """
        new_retry = Retry(
            total=self.total - 1,
            status_forcelist=self.status_forcelist,
            allowed_methods=self.allowed_methods,
            backoff_strategy=self.backoff_strategy,
            respect_retry_after_header=self.respect_retry_after_header,
            retry_on_timeout=self.retry_on_timeout,
            retry_on_connection_error=self.retry_on_connection_error,
            raise_on_status=self.raise_on_status,
            raise_on_redirect=self.raise_on_redirect,
            history=self.history.copy()
        )
        
        # Add this attempt to history
        new_retry.history.append({
            'method': method,
            'url': url,
            'status': response.status if response else None,
            'error': str(error) if error else None,
            'attempt': len(self.history) + 1
        })
        
        return new_retry
