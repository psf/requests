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

if __name__ == '__main__':
    unittest.main()
