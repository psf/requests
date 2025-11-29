"""
Tests for requests.metrics module
"""

import time
import threading
import pytest
from unittest.mock import Mock, patch

from requests.metrics import Stats, MetricsAdapter
from requests.adapters import HTTPAdapter
from requests.models import Response, Request
from requests.exceptions import RequestException


class TestStats:
    """Test cases for Stats class."""
    
    def test_basic_counting(self):
        """Test basic request counting functionality."""
        stats = Stats()
        
        # Record some successful requests
        stats.record(status_code=200, response_time=0.1)
        stats.record(status_code=200, response_time=0.2)
        stats.record(status_code=404, response_time=0.05)
        
        assert stats.total_requests == 3
        assert stats.total_errors == 0
        assert stats.status_distribution[200] == 2
        assert stats.status_distribution[404] == 1
        assert len(stats.response_times) == 3
    
    def test_status_distribution(self):
        """Test status code distribution tracking."""
        stats = Stats()
        
        # Record various status codes
        status_codes = [200, 200, 201, 404, 500, 200, 301]
        for code in status_codes:
            stats.record(status_code=code, response_time=0.1)
        
        distribution = stats.status_distribution
        assert distribution[200] == 3
        assert distribution[201] == 1
        assert distribution[404] == 1
        assert distribution[500] == 1
        assert distribution[301] == 1
        assert sum(distribution.values()) == 7
    
    def test_error_counting(self):
        """Test error counting functionality."""
        stats = Stats()
        
        # Record some successful and failed requests
        stats.record(status_code=200, response_time=0.1)
        stats.record(error=True)  # Network error
        stats.record(status_code=500, response_time=0.2)
        stats.record(error=True)  # Timeout error
        
        assert stats.total_requests == 4
        assert stats.total_errors == 2
        assert stats.status_distribution[200] == 1
        assert stats.status_distribution[500] == 1
    
    def test_thread_safety(self):
        """Test thread safety of Stats class."""
        stats = Stats()
        num_threads = 10
        requests_per_thread = 100
        
        def worker():
            for i in range(requests_per_thread):
                if i % 10 == 0:  # 10% errors
                    stats.record(error=True)
                else:
                    status = 200 if i % 2 == 0 else 201
                    stats.record(status_code=status, response_time=0.01)
        
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify totals
        expected_total = num_threads * requests_per_thread
        expected_errors = num_threads * (requests_per_thread // 10)
        expected_success = expected_total - expected_errors
        
        assert stats.total_requests == expected_total
        assert stats.total_errors == expected_errors
        assert stats.status_distribution[200] + stats.status_distribution[201] == expected_success
    
    def test_reset(self):
        """Test reset functionality."""
        stats = Stats()
        
        # Record some data
        stats.record(status_code=200, response_time=0.1)
        stats.record(status_code=404, response_time=0.05)
        stats.record(error=True)
        
        assert stats.total_requests == 3
        assert stats.total_errors == 1
        assert len(stats.status_distribution) == 2
        assert len(stats.response_times) == 2
        
        # Reset and verify
        stats.reset()
        
        assert stats.total_requests == 0
        assert stats.total_errors == 0
        assert len(stats.status_distribution) == 0
        assert len(stats.response_times) == 0
    
    def test_summary_statistics(self):
        """Test summary statistics calculation."""
        stats = Stats()
        
        # Record response times
        response_times = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        for rt in response_times:
            stats.record(status_code=200, response_time=rt)
        
        summary = stats.get_summary()
        
        assert summary['total_requests'] == 10
        assert summary['total_errors'] == 0
        assert summary['success_rate'] == 100.0
        assert summary['avg_response_time'] == 0.55
        assert summary['min_response_time'] == 0.1
        assert summary['max_response_time'] == 1.0
        # Allow some tolerance for percentile calculation
        assert 0.5 <= summary['p50_response_time'] <= 0.6
        assert 0.9 <= summary['p95_response_time'] <= 1.0
        assert 0.9 <= summary['p99_response_time'] <= 1.0
    
    def test_string_representation(self):
        """Test string representation of Stats."""
        stats = Stats()
        stats.record(status_code=200, response_time=0.1)
        stats.record(status_code=404, response_time=0.05)
        
        str_repr = str(stats)
        assert "Total Requests: 2" in str_repr
        assert "Total Errors: 0" in str_repr
        assert "Success Rate: 100.00%" in str_repr
        assert "200: 1" in str_repr
        assert "404: 1" in str_repr


class TestMetricsAdapter:
    """Test cases for MetricsAdapter class."""
    
    def test_adapter_initialization(self):
        """Test MetricsAdapter initialization."""
        adapter = MetricsAdapter()
        
        assert isinstance(adapter._adapter, HTTPAdapter)
        assert isinstance(adapter._stats, Stats)
        assert adapter.stats is adapter._stats
    
    def test_adapter_with_custom_adapter(self):
        """Test MetricsAdapter with custom HTTPAdapter."""
        custom_adapter = HTTPAdapter()
        adapter = MetricsAdapter(adapter=custom_adapter)
        
        assert adapter._adapter is custom_adapter
        assert isinstance(adapter._stats, Stats)
    
    def test_adapter_with_custom_stats(self):
        """Test MetricsAdapter with custom Stats."""
        custom_stats = Stats()
        adapter = MetricsAdapter(stats=custom_stats)
        
        assert adapter._stats is custom_stats
        assert isinstance(adapter._adapter, HTTPAdapter)
    
    @patch('requests.adapters.HTTPAdapter.send')
    def test_successful_request_metrics(self, mock_send):
        """Test metrics collection for successful requests."""
        # Create mock response
        mock_response = Mock(spec=Response)
        mock_response.status_code = 200
        mock_send.return_value = mock_response
        
        adapter = MetricsAdapter()
        request = Mock(spec=Request)
        request.url = "http://example.com"
        
        # Make request
        response = adapter.send(request)
        
        # Verify response
        assert response is mock_response
        
        # Verify metrics
        assert adapter.stats.total_requests == 1
        assert adapter.stats.total_errors == 0
        assert adapter.stats.status_distribution[200] == 1
        assert len(adapter.stats.response_times) == 1
        assert adapter.stats.response_times[0] >= 0
    
    @patch('requests.adapters.HTTPAdapter.send')
    def test_error_request_metrics(self, mock_send):
        """Test metrics collection for failed requests."""
        mock_send.side_effect = RequestException("Network error")
        
        adapter = MetricsAdapter()
        request = Mock(spec=Request)
        request.url = "http://example.com"
        
        # Make request and expect exception
        with pytest.raises(RequestException):
            adapter.send(request)
        
        # Verify metrics
        assert adapter.stats.total_requests == 1
        assert adapter.stats.total_errors == 1
        assert len(adapter.stats.status_distribution) == 0
        assert len(adapter.stats.response_times) == 1
    
    @patch('requests.adapters.HTTPAdapter.send')
    def test_general_exception_metrics(self, mock_send):
        """Test metrics collection for general exceptions."""
        mock_send.side_effect = ValueError("Unexpected error")
        
        adapter = MetricsAdapter()
        request = Mock(spec=Request)
        request.url = "http://example.com"
        
        # Make request and expect exception
        with pytest.raises(ValueError):
            adapter.send(request)
        
        # Verify metrics
        assert adapter.stats.total_requests == 1
        assert adapter.stats.total_errors == 1
        assert len(adapter.stats.status_distribution) == 0
        assert len(adapter.stats.response_times) == 1
    
    def test_adapter_delegation(self):
        """Test that MetricsAdapter delegates to underlying adapter."""
        custom_adapter = Mock(spec=HTTPAdapter)
        # Add the method we want to test to the mock's spec
        custom_adapter.some_method = Mock(return_value="method_result")
        adapter = MetricsAdapter(adapter=custom_adapter)
        
        # Test attribute delegation
        custom_adapter.some_attribute = "test_value"
        assert adapter.some_attribute == "test_value"
        
        # Test method delegation
        result = adapter.some_method("arg1", "arg2")
        custom_adapter.some_method.assert_called_once_with("arg1", "arg2")
        assert result == "method_result"
    
    def test_adapter_close(self):
        """Test that close method is properly delegated."""
        custom_adapter = Mock(spec=HTTPAdapter)
        adapter = MetricsAdapter(adapter=custom_adapter)
        
        adapter.close()
        custom_adapter.close.assert_called_once()


class TestMetricsIntegration:
    """Integration tests for metrics functionality."""
    
    def test_multiple_requests_metrics(self):
        """Test metrics collection across multiple requests."""
        adapter = MetricsAdapter()
        
        # Mock different response scenarios
        success_response = Mock(spec=Response)
        success_response.status_code = 200
        
        not_found_response = Mock(spec=Response)
        not_found_response.status_code = 404
        
        server_error_response = Mock(spec=Response)
        server_error_response.status_code = 500
        
        with patch('requests.adapters.HTTPAdapter.send') as mock_send:
            # Simulate different response scenarios
            mock_send.side_effect = [
                success_response,
                success_response,
                not_found_response,
                server_error_response,
                RequestException("Timeout")
            ]
            
            request = Mock(spec=Request)
            request.url = "http://example.com"
            
            # Make requests
            adapter.send(request)  # 200
            adapter.send(request)  # 200
            adapter.send(request)  # 404
            adapter.send(request)  # 500
            
            with pytest.raises(RequestException):
                adapter.send(request)  # Error
            
            # Verify final metrics
            assert adapter.stats.total_requests == 5
            assert adapter.stats.total_errors == 1
            assert adapter.stats.status_distribution[200] == 2
            assert adapter.stats.status_distribution[404] == 1
            assert adapter.stats.status_distribution[500] == 1
            assert len(adapter.stats.response_times) == 5
    
    def test_response_time_accuracy(self):
        """Test that response times are accurately recorded."""
        adapter = MetricsAdapter()
        
        # Mock response with controlled delay
        def mock_send_with_delay(*args, **kwargs):
            time.sleep(0.1)  # 100ms delay
            response = Mock(spec=Response)
            response.status_code = 200
            return response
        
        with patch('requests.adapters.HTTPAdapter.send', side_effect=mock_send_with_delay):
            request = Mock(spec=Request)
            request.url = "http://example.com"
            
            start_time = time.time()
            adapter.send(request)
            actual_time = time.time() - start_time
            
            # Verify response time is recorded
            assert len(adapter.stats.response_times) == 1
            recorded_time = adapter.stats.response_times[0]
            
            # Allow some tolerance for timing
            assert 0.09 <= recorded_time <= 0.11
            assert abs(recorded_time - actual_time) < 0.02