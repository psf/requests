#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

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

    def test_HTTP_200_OK_GET_WITH_PARAMS(self):

        heads = {'User-agent': 'Mozilla/5.0'}
        
        r = requests.get('http://www.google.com/search', params={'q': 'test'}, headers=heads)
        self.assertEqual(r.status_code, 200)


    def test_HTTP_200_OK_GET_WITH_MIXED_PARAMS(self):

        heads = {'User-agent': 'Mozilla/5.0'}

        r = requests.get('http://google.com/search?test=true', params={'q': 'test'}, headers=heads)
        self.assertEqual(r.status_code, 200)
        
    def test_HTTP_200_OK_HEAD(self):
        r = requests.head('http://google.com')
        self.assertEqual(r.status_code, 200)

    def test_HTTPS_200_OK_HEAD(self):
        r = requests.head('https://google.com')
        self.assertEqual(r.status_code, 200)

    def test_AUTH_HTTPS_200_OK_GET(self):
        auth = ('requeststest', 'requeststest')
        url = 'https://convore.com/api/account/verify.json'
        r = requests.get(url, auth=auth)

        self.assertEqual(r.status_code, 200)

        r = requests.get(url)
        self.assertEqual(r.status_code, 200)

        # reset auto authentication
        requests.auth_manager.empty()

    def test_POSTBIN_GET_POST_FILES(self):

        bin = requests.post('http://www.postbin.org/')
        print bin.url
        self.assertEqual(bin.status_code, 200)
        
        post = requests.post(bin.url, data={'some': 'data'})
        self.assertEqual(post.status_code, 201)

        post2 = requests.post(bin.url, files={'some': open('test_requests.py')})
        self.assertEqual(post2.status_code, 201)

    def test_POSTBIN_GET_POST_FILES_WITH_PARAMS(self):

        bin = requests.post('http://www.postbin.org/')
        
        self.assertEqual(bin.status_code, 200)

        post2 = requests.post(bin.url, files={'some': open('test_requests.py')}, data={'some': 'data'})
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
