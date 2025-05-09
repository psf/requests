#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import time
from unittest import mock

import requests
from requests.retry import (
    Retry,
    ConstantRetry,
    ExponentialRetry,
    ExponentialRetryWithJitter,
    RetryStrategy,
)


class TestRetryStrategies(unittest.TestCase):
    def test_constant_retry(self):
        strategy = ConstantRetry(backoff_factor=2.0)
        self.assertEqual(strategy.get_backoff_time(0), 2.0)
        self.assertEqual(strategy.get_backoff_time(1), 2.0)
        self.assertEqual(strategy.get_backoff_time(2), 2.0)

    def test_exponential_retry(self):
        strategy = ExponentialRetry(backoff_factor=1.0, max_backoff=10.0)
        self.assertEqual(strategy.get_backoff_time(0), 1.0)
        self.assertEqual(strategy.get_backoff_time(1), 2.0)
        self.assertEqual(strategy.get_backoff_time(2), 4.0)
        self.assertEqual(strategy.get_backoff_time(3), 8.0)
        # Should be capped at max_backoff
        self.assertEqual(strategy.get_backoff_time(4), 10.0)

    def test_exponential_retry_with_jitter(self):
        # Mock random.uniform to return a predictable value
        with mock.patch('random.uniform', return_value=0.1):
            strategy = ExponentialRetryWithJitter(
                backoff_factor=1.0, max_backoff=10.0, jitter_factor=0.5
            )
            # With jitter_factor=0.5 and mocked random.uniform=0.1:
            # jitter = backoff * jitter_factor = 1.0 * 0.5 = 0.5
            # random.uniform(-0.5, 0.5) = 0.1
            # backoff + jitter = 1.0 + 0.1 = 1.1
            self.assertAlmostEqual(strategy.get_backoff_time(0), 1.1)
            # For retry 1: backoff = 2.0, jitter = 2.0 * 0.5 = 1.0
            # backoff + random.uniform(-1.0, 1.0) = 2.0 + 0.1 = 2.1
            self.assertAlmostEqual(strategy.get_backoff_time(1), 2.1)


class TestRetry(unittest.TestCase):
    def test_retry_initialization(self):
        retry = Retry(
            total=5,
            status_forcelist={500, 502},
            allowed_methods={'GET', 'POST'},
            backoff_strategy=ConstantRetry(2.0),
            retry_on_timeout=True,
        )
        
        self.assertEqual(retry.total, 5)
        self.assertEqual(retry.status_forcelist, {500, 502})
        self.assertEqual(retry.allowed_methods, {'GET', 'POST'})
        self.assertTrue(retry.retry_on_timeout)
        self.assertIsInstance(retry.backoff_strategy, ConstantRetry)
        
    def test_retry_increment(self):
        retry = Retry(total=3)
        new_retry = retry.increment(method='GET', url='https://example.com')
        
        self.assertEqual(new_retry.total, 2)
        self.assertEqual(len(new_retry.history), 1)
        self.assertEqual(new_retry.history[0]['method'], 'GET')
        self.assertEqual(new_retry.history[0]['url'], 'https://example.com')
        self.assertEqual(new_retry.history[0]['attempt'], 1)


class TestSessionRetry(unittest.TestCase):
    @mock.patch('requests.adapters.HTTPAdapter.send')
    def test_session_retry_configuration(self, mock_send):
        # Mock response
        mock_response = requests.Response()
        mock_response.status_code = 200
        mock_send.return_value = mock_response
        
        # Create session with retry configuration
        session = requests.Session()
        session.max_retries = 3
        session.retry_status_forcelist = {500, 502}
        session.retry_on_timeout = True
        
        # Make a request
        session.get('https://example.com')
        
        # Check that the adapter's max_retries was configured correctly
        adapter = session.get_adapter('https://example.com')
        self.assertEqual(adapter.max_retries.total, 3)
        self.assertEqual(adapter.max_retries.status_forcelist, {500, 502})


if __name__ == '__main__':
    unittest.main()
