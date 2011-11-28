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


if __name__ == '__main__':
    unittest.main()
