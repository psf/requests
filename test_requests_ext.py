#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement

import unittest

import requests

try:
    import omnijson as json
except ImportError:
    import json


class RequestsTestSuite(unittest.TestCase):
    """Requests test cases."""

    # It goes to eleven.
    _multiprocess_can_split_ = True

    def test_addition(self):
        assert (1 + 1) == 2

    def test_ssl_hostname_ok(self):
        requests.get('https://github.com', verify=True)

    def test_ssl_hostname_not_ok(self):
        requests.get('https://kennethreitz.com', verify=False)

        self.assertRaises(requests.exceptions.SSLError, requests.get, 'https://kennethreitz.com')

    def test_ssl_hostname_session_not_ok(self):

        s = requests.session()

        s.get('https://kennethreitz.com', verify=False)

        self.assertRaises(requests.exceptions.SSLError, s.get, 'https://kennethreitz.com')



if __name__ == '__main__':
    unittest.main()

