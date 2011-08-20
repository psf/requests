#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement

import unittest
import cookielib

try:
    import omnijson as json
except ImportError:
    import json

import requests



HTTPBIN_URL = 'http://httpbin.org/'
HTTPSBIN_URL = 'https://httpbin.ep.io/'

# HTTPBIN_URL = 'http://staging.httpbin.org/'
# HTTPSBIN_URL = 'https://httpbin-staging.ep.io/'


def httpbin(*suffix):
    """Returns url for HTTPBIN resource."""

    return HTTPBIN_URL + '/'.join(suffix)


def httpsbin(*suffix):
    """Returns url for HTTPSBIN resource."""

    return HTTPSBIN_URL + '/'.join(suffix)


SERVICES = (httpbin, httpsbin)



class RequestsTestSuite(unittest.TestCase):
    """Requests test cases."""


    def setUp(self):
        pass


    def tearDown(self):
        """Teardown."""
        pass


    def test_HTTP_200_OK_GET_ON_ISO88591(self):
        r = requests.get("http://www.qypedeals.de/Verzehrgutschein+für+Jellyfish")
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.content, unicode)
    
    def test_HTTP_200_OK_GET_ON_BIG5(self):
        r = requests.get("http://google.com.hk/")
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.content, unicode)


if __name__ == '__main__':
    unittest.main()
