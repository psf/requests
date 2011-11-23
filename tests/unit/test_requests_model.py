#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import mock
import sys
import os
sys.path.append(os.getcwd())

from requests import models

class RequestsModelUnitTests(unittest.TestCase):
    """Requests API unit test cases."""

    def setUp(self):
        pass


    def tearDown(self):
        """Teardown."""
        pass

    @mock.patch('requests.models.dispatch_hook')
    def test_Request_init(self, mock_dispatch):
        r = models.Request(url="google.com", method='get')

        mock_dispatch.assert_called_once_with('pre_request', None, r)

        self.assertEqual('get',r.method)
        self.assertEqual('google.com',r.url)
        self.assertEqual(None,r.timeout)
        self.assertEqual(None,r.files)
        self.assertEqual([],r.data)
        self.assertEqual([],r.params)
        self.assertEqual({},r.proxies)
        self.assertEqual({},r.headers)
        self.assertEqual(False,r.redirect)
        self.assertEqual(False,r.allow_redirects)
        self.assertEqual(None,r.hooks)
        self.assertEqual({},r.config)

    @mock.patch('requests.models.dispatch_hook')
    def test_Request_init_no_args(self, mock_dispatch):
        r = models.Request()

        mock_dispatch.assert_called_once_with('pre_request', None, r)
        self.assertEqual(None,r.method)
        self.assertEqual(None,r.url)
        self.assertEqual(None,r.timeout)
        self.assertEqual(None,r.files)
        self.assertEqual([],r.data)
        self.assertEqual([],r.params)
        self.assertEqual({},r.proxies)
        self.assertEqual({},r.headers)
        self.assertEqual(False,r.redirect)
        self.assertEqual(False,r.allow_redirects)
        self.assertEqual(None,r.hooks)
        self.assertEqual({},r.config)

    def test_Request_encode_params(self):
        l,e = models.Request._encode_params({"foo": "bar", "baz": "bla"})
        self.assertEqual([("foo","bar"), ("baz", "bla")], l)
        self.assertEqual("foo=bar&baz=bla", e)

    def test_Request_encode_params_from_string(self):
        l,e = models.Request._encode_params("foobarbazbla")
        self.assertEqual("foobarbazbla", l)
        self.assertEqual("foobarbazbla", e)





if __name__ == '__main__':
    unittest.main()
