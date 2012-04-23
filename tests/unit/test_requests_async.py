#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import mock
import sys
import os
sys.path.append(os.getcwd())

from requests import async

class RequestsAsyncUnitTests(unittest.TestCase):
    """Requests async unit test cases."""

    def setUp(self):
        pass


    def tearDown(self):
        """Teardown."""
        pass

    def test_async_patched(self):
        fun = mock.Mock()
        f = async.patched(fun)
        f()
        fun.assert_called_with(return_response=False, prefetch=True)

    def test_async_send(self):
        req = mock.Mock()
        req.response = 'response'
        resp = async.send(req)
        req.send.assert_called_once()
        self.assertEqual('response', resp)

    def test_async_send_with_pools(self):
        req = mock.Mock()
        pools = mock.Mock()
        req.response = 'response'
        resp = async.send(req, pools)
        req.send.assert_called_once()
        self.assertEqual('response', resp)
        self.assertEqual(pools, req._pools)

    @mock.patch('requests.async.gevent')
    def test_async_map(self, mock_gevent):
        req = mock.MagicMock()
        resp = async.map(req)
        self.assertEqual([], resp)

    @mock.patch('requests.async.gevent')
    def test_async_map_without_prefetch(self, mock_gevent):
        req = mock.MagicMock()
        resp = async.map(req, prefetch=False)
        self.assertEqual([], resp)

    @mock.patch('requests.async.Pool')
    def test_async_map_with_size(self, mock_pool):
        mock_ret_pool = mock.Mock()
        mock_pool.return_value = mock_ret_pool
        req = mock.MagicMock()
        resp = async.map(req, size=10)
        self.assertEqual([], resp)
        mock_pool.assert_called_with(10)
        mock_ret_pool.map.assert_called__once_with(async.send, req)
        mock_ret_pool.join.assert_called_once()




if __name__ == '__main__':
    unittest.main()
