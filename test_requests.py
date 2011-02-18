#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import unittest

if sys.version_info >= (3,0):
    from io import StringIO
else:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

import requests


class RequestsTestSuite(unittest.TestCase):
    """Requests test cases."""
    
    def setUp(self):
        pass

    def tearDown(self):
        """Teardown."""
        pass
        
    def test_invalid_url(self):
        self.assertRaises(ValueError, requests.get, 'hiwpefhipowhefopw')


    def test_HTTP_200_OK_GET(self):
        r = requests.get('http://google.com')
        self.assertEqual(r.status_code, 200)


    def test_HTTPS_200_OK_GET(self):
        r = requests.get('https://google.com')
        self.assertEqual(r.status_code, 200)


    def test_HTTP_200_OK_HEAD(self):
        r = requests.head('http://google.com')
        self.assertEqual(r.status_code, 200)


    def test_HTTPS_200_OK_HEAD(self):
        r = requests.head('https://google.com')
        self.assertEqual(r.status_code, 200)


    def test_AUTH_HTTPS_200_OK_GET(self):
        auth = requests.AuthObject('requeststest', 'requeststest')
        url = 'https://convore.com/api/account/verify.json'
        r = requests.get(url, auth=auth)

        self.assertEqual(r.status_code, 200)


    def test_POSTBIN_GET_POST_FILES(self):

        bin = requests.post('http://www.postbin.org/')
        self.assertEqual(bin.status_code, 200)

        post = requests.post(bin.url, data={'some': 'data'})
        self.assertEqual(post.status_code, 201)

        post2 = requests.post(bin.url, files={'some': StringIO('data')})
        self.assertEqual(post2.status_code, 201)


    def test_nonzero_evaluation(self):
        r = requests.get('http://google.com/some-404-url')
        self.assertEqual(bool(r), False)
    
        r = requests.get('http://google.com/')
        self.assertEqual(bool(r), True)


    def test_request_ok_set(self):
        r = requests.get('http://google.com/some-404-url')
        self.assertEqual(r.ok, False)


    def test_status_raising(self):
        r = requests.get('http://google.com/some-404-url')
        self.assertRaises(requests.HTTPError, r.raise_for_status)

        r = requests.get('http://google.com/')
        self.assertFalse(r.error)
        r.raise_for_status()


if __name__ == '__main__':
    unittest.main()
