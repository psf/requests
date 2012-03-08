#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Path hack.
import sys, os
sys.path.insert(0, os.path.abspath('..'))

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

        self.assertRaises(requests.exceptions.SSLError, s.get, 'https://kennethreitz.com')

        s.get('https://kennethreitz.com', verify=False)


    def test_binary_post(self):
        utf8_string = (u'Smörgås').encode('utf-8')
        requests.post('http://www.google.com/', data=utf8_string)


    def test_unicode_error(self):
        url = u'http://blip.fm/~1abvfu'
        requests.get(url)

if __name__ == '__main__':
    unittest.main()

