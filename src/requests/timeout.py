"""
requests.timeout
~~~~~~~~~~~~~

This module provides enhanced timeout functionality for the requests library.
"""

from typing import Dict, Optional, Union, Any, Tuple
import logging

logger = logging.getLogger(__name__)


class Timeout:
    """
    Timeout configuration with granular control over different phases of the request.
    
    This class allows for specifying different timeouts for different phases of the
    request lifecycle, such as connection establishment, sending data, and receiving
    the response.
    """
    
    def __init__(
        self,
        total: Optional[float] = None,
        connect: Optional[float] = None,
        read: Optional[float] = None,
        write: Optional[float] = None,
        pool: Optional[float] = None,
    ):
        """
        Initialize a Timeout object.
        
        :param total: Total timeout for the entire request (overrides others if they're not set)
        :param connect: Timeout for connection establishment
        :param read: Timeout for reading the response
        :param write: Timeout for writing the request
        :param pool: Timeout for getting a connection from the pool
        """
        self.total = total
        self.connect = connect if connect is not None else total
        self.read = read if read is not None else total
        self.write = write if write is not None else total
        self.pool = pool if pool is not None else total
    
    @classmethod
    def from_value(cls, value: Union[float, Tuple[float, float], 'Timeout', None]) -> 'Timeout':
        """
        Create a Timeout object from various input formats.
        
        :param value: Can be:
            - None: No timeout
            - float: Total timeout
            - tuple: (connect_timeout, read_timeout)
            - Timeout: Existing Timeout object
        :return: A Timeout object
        """
        if value is None:
            return cls()
        
        if isinstance(value, (int, float)):
            return cls(total=float(value))
        
        if isinstance(value, tuple) and len(value) == 2:
            connect, read = value
            return cls(connect=connect, read=read)
        
        if isinstance(value, Timeout):
            return value
        
        raise ValueError(
            f"Invalid timeout value: {value}. Must be a number, tuple of two numbers, or Timeout object."
        )
    
    def to_urllib3_timeout(self) -> Union[float, Tuple[float, float], None]:
        """
        Convert to a format that urllib3 understands.
        
        :return: A urllib3-compatible timeout value
        """
        if self.connect is not None and self.read is not None:
            return (self.connect, self.read)
        
        if self.total is not None:
            return self.total
        
        return None
    
    def __repr__(self) -> str:
        attrs = []
        for attr in ['total', 'connect', 'read', 'write', 'pool']:
            value = getattr(self, attr)
            if value is not None:
                attrs.append(f"{attr}={value}")
        
        return f"Timeout({', '.join(attrs)})"


class TimeoutStrategy:
    """Base class for timeout strategies."""
    
    def get_timeout(self, retry_number: int) -> Timeout:
        """
        Get the timeout for the current retry attempt.
        
        :param retry_number: The current retry attempt (0-based)
        :return: A Timeout object
        """
        raise NotImplementedError("Timeout strategies must implement get_timeout")


class ConstantTimeout(TimeoutStrategy):
    """Strategy that uses a constant timeout for all retry attempts."""
    
    def __init__(self, timeout: Timeout):
        """
        Initialize a constant timeout strategy.
        
        :param timeout: The timeout to use for all retry attempts
        """
        self.timeout = timeout
    
    def get_timeout(self, retry_number: int) -> Timeout:
        """
        Get the constant timeout.
        
        :param retry_number: The current retry attempt (0-based)
        :return: The constant timeout
        """
        return self.timeout


class LinearTimeout(TimeoutStrategy):
    """Strategy that increases the timeout linearly with each retry attempt."""
    
    def __init__(
        self,
        base_timeout: Timeout,
        increment: float = 1.0,
        max_timeout: Optional[float] = None
    ):
        """
        Initialize a linear timeout strategy.
        
        :param base_timeout: The base timeout for the first attempt
        :param increment: The amount to increase the timeout by for each retry
        :param max_timeout: Maximum timeout value (if None, no maximum)
        """
        self.base_timeout = base_timeout
        self.increment = increment
        self.max_timeout = max_timeout
    
    def get_timeout(self, retry_number: int) -> Timeout:
        """
        Get the timeout for the current retry attempt.
        
        :param retry_number: The current retry attempt (0-based)
        :return: The timeout for this attempt
        """
        # Calculate the new total timeout
        base_total = self.base_timeout.total or 0
        new_total = base_total + (retry_number * self.increment)
        
        # Apply maximum if specified
        if self.max_timeout is not None:
            new_total = min(new_total, self.max_timeout)
        
        # Create a new timeout with the same structure but adjusted values
        new_timeout = Timeout(
            total=new_total,
            connect=self._scale_value(self.base_timeout.connect, base_total, new_total),
            read=self._scale_value(self.base_timeout.read, base_total, new_total),
            write=self._scale_value(self.base_timeout.write, base_total, new_total),
            pool=self._scale_value(self.base_timeout.pool, base_total, new_total),
        )
        
        return new_timeout
    
    def _scale_value(self, value: Optional[float], old_total: float, new_total: float) -> Optional[float]:
        """Scale a timeout value proportionally to the change in total timeout."""
        if value is None or old_total == 0:
            return None
        
        # Scale the value proportionally
        return value * (new_total / old_total) if old_total else value


class ExponentialTimeout(TimeoutStrategy):
    """Strategy that increases the timeout exponentially with each retry attempt."""
    
    def __init__(
        self,
        base_timeout: Timeout,
        factor: float = 2.0,
        max_timeout: Optional[float] = None
    ):
        """
        Initialize an exponential timeout strategy.
        
        :param base_timeout: The base timeout for the first attempt
        :param factor: The factor to multiply the timeout by for each retry
        :param max_timeout: Maximum timeout value (if None, no maximum)
        """
        self.base_timeout = base_timeout
        self.factor = factor
        self.max_timeout = max_timeout
    
    def get_timeout(self, retry_number: int) -> Timeout:
        """
        Get the timeout for the current retry attempt.
        
        :param retry_number: The current retry attempt (0-based)
        :return: The timeout for this attempt
        """
        # Calculate the new total timeout
        base_total = self.base_timeout.total or 0
        new_total = base_total * (self.factor ** retry_number)
        
        # Apply maximum if specified
        if self.max_timeout is not None:
            new_total = min(new_total, self.max_timeout)
        
        # Create a new timeout with the same structure but adjusted values
        new_timeout = Timeout(
            total=new_total,
            connect=self._scale_value(self.base_timeout.connect, base_total, new_total),
            read=self._scale_value(self.base_timeout.read, base_total, new_total),
            write=self._scale_value(self.base_timeout.write, base_total, new_total),
            pool=self._scale_value(self.base_timeout.pool, base_total, new_total),
        )
        
        return new_timeout
    
    def _scale_value(self, value: Optional[float], old_total: float, new_total: float) -> Optional[float]:
        """Scale a timeout value proportionally to the change in total timeout."""
        if value is None or old_total == 0:
            return None
        
        # Scale the value proportionally
        return value * (new_total / old_total) if old_total else value
