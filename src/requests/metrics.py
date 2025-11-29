"""
requests.metrics
~~~~~~~~~~~~~~

This module provides metrics collection functionality for requests.

:copyright: (c) 2024 by requests team.
:license: Apache 2.0, see LICENSE for more details.
"""

import time
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Any, Union

from .adapters import HTTPAdapter
from .models import Response
from .exceptions import RequestException


class Stats:
    """Thread-safe statistics collector for HTTP requests."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._total_requests = 0
        self._total_errors = 0
        self._status_distribution = defaultdict(int)
        self._response_times = []
        self._max_response_times = 1000  # Keep last 1000 response times
    
    def record(self, status_code: Optional[int] = None, response_time: Optional[float] = None, 
               error: bool = False) -> None:
        """
        Record a request metric.
        
        Args:
            status_code: HTTP status code (None if error)
            response_time: Response time in seconds
            error: Whether this was an error
        """
        with self._lock:
            self._total_requests += 1
            
            if error:
                self._total_errors += 1
            elif status_code:
                self._status_distribution[status_code] += 1
            
            if response_time is not None:
                self._response_times.append(response_time)
                # Keep only the last max_response_times entries
                if len(self._response_times) > self._max_response_times:
                    self._response_times = self._response_times[-self._max_response_times:]
    
    @property
    def total_requests(self) -> int:
        """Get total number of requests."""
        with self._lock:
            return self._total_requests
    
    @property
    def total_errors(self) -> int:
        """Get total number of errors."""
        with self._lock:
            return self._total_errors
    
    @property
    def status_distribution(self) -> Dict[int, int]:
        """Get status code distribution."""
        with self._lock:
            return dict(self._status_distribution)
    
    @property
    def response_times(self) -> List[float]:
        """Get list of response times."""
        with self._lock:
            return self._response_times.copy()
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all statistics.
        
        Returns:
            Dictionary containing all statistics
        """
        with self._lock:
            summary = {
                'total_requests': self._total_requests,
                'total_errors': self._total_errors,
                'success_rate': 0.0 if self._total_requests == 0 else 
                               (self._total_requests - self._total_errors) / self._total_requests * 100,
                'status_distribution': dict(self._status_distribution),
                'total_response_times': len(self._response_times)
            }
            
            if self._response_times:
                summary.update({
                    'avg_response_time': sum(self._response_times) / len(self._response_times),
                    'min_response_time': min(self._response_times),
                    'max_response_time': max(self._response_times),
                    'p50_response_time': self._percentile(50),
                    'p95_response_time': self._percentile(95),
                    'p99_response_time': self._percentile(99)
                })
            else:
                summary.update({
                    'avg_response_time': None,
                    'min_response_time': None,
                    'max_response_time': None,
                    'p50_response_time': None,
                    'p95_response_time': None,
                    'p99_response_time': None
                })
            
            return summary
    
    def _percentile(self, p: int) -> Optional[float]:
        """Calculate percentile of response times."""
        if not self._response_times:
            return None
        
        sorted_times = sorted(self._response_times)
        index = int(len(sorted_times) * p / 100)
        if index >= len(sorted_times):
            index = len(sorted_times) - 1
        return sorted_times[index]
    
    def reset(self) -> None:
        """Reset all statistics."""
        with self._lock:
            self._total_requests = 0
            self._total_errors = 0
            self._status_distribution.clear()
            self._response_times.clear()
    
    def __str__(self) -> str:
        """String representation of statistics."""
        summary = self.get_summary()
        lines = [
            f"=== Request Metrics Summary ===",
            f"Total Requests: {summary['total_requests']}",
            f"Total Errors: {summary['total_errors']}",
            f"Success Rate: {summary['success_rate']:.2f}%"
        ]
        
        if summary['status_distribution']:
            lines.append("Status Code Distribution:")
            for status, count in sorted(summary['status_distribution'].items()):
                lines.append(f"  {status}: {count}")
        
        if summary['total_response_times'] > 0:
            lines.extend([
                f"Response Times (s):",
                f"  Count: {summary['total_response_times']}",
                f"  Average: {summary['avg_response_time']:.4f}",
                f"  Min: {summary['min_response_time']:.4f}",
                f"  Max: {summary['max_response_time']:.4f}",
                f"  P50: {summary['p50_response_time']:.4f}",
                f"  P95: {summary['p95_response_time']:.4f}",
                f"  P99: {summary['p99_response_time']:.4f}"
            ])
        
        return '\n'.join(lines)


class MetricsAdapter(HTTPAdapter):
    """
    HTTPAdapter that collects metrics without changing behavior.
    
    This adapter wraps another HTTPAdapter and records timing and status code
    information for all requests.
    """
    
    def __init__(self, adapter: Optional[HTTPAdapter] = None, stats: Optional[Stats] = None):
        """
        Initialize MetricsAdapter.
        
        Args:
            adapter: The HTTPAdapter to wrap. If None, creates a new one.
            stats: Stats instance to use. If None, creates a new one.
        """
        super().__init__()
        self._adapter = adapter or HTTPAdapter()
        self._stats = stats or Stats()
    
    @property
    def stats(self) -> Stats:
        """Get the stats collector."""
        return self._stats
    
    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """
        Send a request and collect metrics.
        
        Args:
            request: The request to send
            stream: Whether to stream the response
            timeout: Request timeout
            verify: SSL verification
            cert: Client certificate
            proxies: Proxies to use
            
        Returns:
            Response object
        """
        start_time = time.time()
        
        try:
            response = self._adapter.send(
                request, stream=stream, timeout=timeout, 
                verify=verify, cert=cert, proxies=proxies
            )
            
            elapsed_time = time.time() - start_time
            self._stats.record(
                status_code=response.status_code,
                response_time=elapsed_time,
                error=False
            )
            
            return response
            
        except RequestException as e:
            elapsed_time = time.time() - start_time
            self._stats.record(
                status_code=None,
                response_time=elapsed_time,
                error=True
            )
            raise
        except Exception as e:
            elapsed_time = time.time() - start_time
            self._stats.record(
                status_code=None,
                response_time=elapsed_time,
                error=True
            )
            raise
    
    def close(self):
        """Close the underlying adapter."""
        self._adapter.close()
    
    def __getattr__(self, name):
        """Delegate all other attributes to the underlying adapter."""
        return getattr(self._adapter, name)