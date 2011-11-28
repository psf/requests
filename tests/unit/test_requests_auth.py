#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import mock
import sys
import os
sys.path.append(os.getcwd())

from requests import auth

class RequestsAuthUnitTests(unittest.TestCase):
    """Requests auth unit test cases."""

    def setUp(self):
        pass

    def tearDown(self):
        """Teardown."""
        pass

    @mock.patch('requests.auth.b64encode')
    def test_auth_basic_auth(self, enc_mock):
        enc_mock.return_value = 'Zm9vOmJhcg=='
        a = auth.HTTPBasicAuth('foo', 'bar')
        req = mock.MagicMock()
        req.headers = dict()
        res = a(req)
        enc_mock.assert_called_once_with('foo:bar')
        self.assertEqual("Basic Zm9vOmJhcg==", res.headers['Authorization'])


if __name__ == '__main__':
    unittest.main()
