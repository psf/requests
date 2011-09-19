#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import mock
import sys
import os
sys.path.append(os.getcwd())

from requests.hooks import dispatch_hook

class RequestsAPIUnitTests(unittest.TestCase):
    """Requests API unit test cases."""

    def setUp(self):
        self.args_hook = mock.Mock()
        self.pre_hook = mock.Mock()
        self.post_hook = mock.Mock()
        self.response_hook = mock.Mock()
        self.hooks = { "args": self.args_hook,
                       "pre_request": self.pre_hook,
                       "post_request": self.post_hook,
                       "response": self.response_hook
                     }

    def tearDown(self):
        """Teardown."""
        pass

    def test_dispatch_hook_args(self):
        dispatch_hook("args", self.hooks, "called")
        self.args_hook.assert_called_once_with("called")

    def test_dispatch_hook_pre_request(self):
        dispatch_hook("pre_request", self.hooks, "called")
        self.pre_hook.assert_called_once_with("called")

    def test_dispatch_hook_post_request(self):
        dispatch_hook("post_request", self.hooks, "called")
        self.post_hook.assert_called_once_with("called")

    def test_dispatch_hook_response(self):
        dispatch_hook("response", self.hooks, "called")
        self.response_hook.assert_called_once_with("called")

if __name__ == '__main__':
    unittest.main()
