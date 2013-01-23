#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for Requests."""

import json
import os
import unittest

import requests
from requests.auth import HTTPDigestAuth
from requests.compat import str

try:
    import StringIO
except ImportError:
    import io as StringIO

HTTPBIN = os.environ.get('HTTPBIN_URL', 'http://httpbin.org/')

def httpbin(*suffix):
    """Returns url for HTTPBIN resource."""
    return HTTPBIN + '/'.join(suffix)

class RequestsTestCase(unittest.TestCase):

    _multiprocess_can_split_ = True

    def setUp(self):
        """Create simple data set with headers."""
        pass

    def tearDown(self):
        """Teardown."""
        pass

    def test_assertion(self):
        assert 1

    def test_entry_points(self):

        requests.session
        requests.session().get
        requests.session().head
        requests.get
        requests.head
        requests.put
        requests.patch
        requests.post

    def test_invalid_url(self):
        self.assertRaises(ValueError, requests.get, 'hiwpefhipowhefopw')

    def test_basic_building(self):
        req = requests.Request()
        req.url = 'http://kennethreitz.org/'
        req.data = {'life': '42'}

        pr = req.prepare()
        assert pr.url == req.url
        assert pr.body == 'life=42'


    def test_path_is_not_double_encoded(self):
        request = requests.Request('GET', "http://0.0.0.0/get/test case").prepare()

        self.assertEqual(request.path_url, "/get/test%20case")

    def test_params_are_added_before_fragment(self):
        request = requests.Request('GET',
            "http://example.com/path#fragment", params={"a": "b"}).prepare()
        self.assertEqual(request.url,
            "http://example.com/path?a=b#fragment")
        request = requests.Request('GET',
            "http://example.com/path?key=value#fragment", params={"a": "b"}).prepare()
        self.assertEqual(request.url,
            "http://example.com/path?key=value&a=b#fragment")

    def test_HTTP_200_OK_GET(self):
        r = requests.get(httpbin('get'))
        self.assertEqual(r.status_code, 200)

    def test_HTTP_200_OK_GET_ALTERNATIVE(self):
        r = requests.Request('GET', httpbin('get'))
        s = requests.Session()

        r = s.send(r.prepare())

        self.assertEqual(r.status_code, 200)

    def test_HTTP_302_ALLOW_REDIRECT_GET(self):
        r = requests.get(httpbin('redirect', '1'))
        self.assertEqual(r.status_code, 200)

    # def test_HTTP_302_ALLOW_REDIRECT_POST(self):
    #     r = requests.post(httpbin('status', '302'), data={'some': 'data'})
    #     self.assertEqual(r.status_code, 200)

    def test_HTTP_200_OK_GET_WITH_PARAMS(self):
        heads = {'User-agent': 'Mozilla/5.0'}

        r = requests.get(httpbin('user-agent'), headers=heads)

        self.assertTrue(heads['User-agent'] in r.text)
        self.assertEqual(r.status_code, 200)

    def test_HTTP_200_OK_GET_WITH_MIXED_PARAMS(self):
        heads = {'User-agent': 'Mozilla/5.0'}

        r = requests.get(httpbin('get') + '?test=true', params={'q': 'test'}, headers=heads)
        self.assertEqual(r.status_code, 200)

    def test_user_agent_transfers(self):

        heads = {
            'User-agent':
                'Mozilla/5.0 (github.com/kennethreitz/requests)'
        }

        r = requests.get(httpbin('user-agent'), headers=heads)
        self.assertTrue(heads['User-agent'] in r.text)

        heads = {
            'user-agent':
                'Mozilla/5.0 (github.com/kennethreitz/requests)'
        }

        r = requests.get(httpbin('user-agent'), headers=heads)
        self.assertTrue(heads['user-agent'] in r.text)

    def test_HTTP_200_OK_HEAD(self):
        r = requests.head(httpbin('get'))
        self.assertEqual(r.status_code, 200)

    def test_HTTP_200_OK_PUT(self):
        r = requests.put(httpbin('put'))
        self.assertEqual(r.status_code, 200)

    def test_BASICAUTH_TUPLE_HTTP_200_OK_GET(self):
        auth = ('user', 'pass')
        url = httpbin('basic-auth', 'user', 'pass')

        r = requests.get(url, auth=auth)
        self.assertEqual(r.status_code, 200)

        r = requests.get(url)
        self.assertEqual(r.status_code, 401)

        s = requests.session()
        s.auth = auth
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_DIGEST_HTTP_200_OK_GET(self):

        auth = HTTPDigestAuth('user', 'pass')
        url = httpbin('digest-auth', 'auth', 'user', 'pass')

        r = requests.get(url, auth=auth)
        self.assertEqual(r.status_code, 200)

        r = requests.get(url)
        self.assertEqual(r.status_code, 401)

        s = requests.session()
        s.auth = auth
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_DIGESTAUTH_WRONG_HTTP_401_GET(self):

        auth = HTTPDigestAuth('user', 'wrongpass')
        url = httpbin('digest-auth', 'auth', 'user', 'pass')

        r = requests.get(url, auth=auth)
        self.assertEqual(r.status_code, 401)

        r = requests.get(url)
        self.assertEqual(r.status_code, 401)

        s = requests.session()
        s.auth = auth
        r = s.get(url)
        self.assertEqual(r.status_code, 401)

    def test_POSTBIN_GET_POST_FILES(self):

        url = httpbin('post')
        post1 = requests.post(url).raise_for_status()

        post1 = requests.post(url, data={'some': 'data'})
        self.assertEqual(post1.status_code, 200)

        with open('requirements.txt') as f:
            post2 = requests.post(url, files={'some': f})
        self.assertEqual(post2.status_code, 200)

        post4 = requests.post(url, data='[{"some": "json"}]')
        self.assertEqual(post4.status_code, 200)

        try:
            requests.post(url, files=['bad file data'])
        except ValueError:
            pass

    def test_POSTBIN_GET_POST_FILES_WITH_DATA(self):

        url = httpbin('post')
        post1 = requests.post(url).raise_for_status()

        post1 = requests.post(url, data={'some': 'data'})
        self.assertEqual(post1.status_code, 200)

        with open('requirements.txt') as f:
            post2 = requests.post(url, data={'some': 'data'}, files={'some': f})
        self.assertEqual(post2.status_code, 200)

        post4 = requests.post(url, data='[{"some": "json"}]')
        self.assertEqual(post4.status_code, 200)

        try:
            requests.post(url, files=['bad file data'])
        except ValueError:
            pass

    def test_request_ok_set(self):
        r = requests.get(httpbin('status', '404'))
        self.assertEqual(r.ok, False)

    def test_status_raising(self):
        r = requests.get(httpbin('status', '404'))
        self.assertRaises(requests.exceptions.HTTPError, r.raise_for_status)

        r = requests.get(httpbin('status', '500'))
        self.assertFalse(r.ok)

    def test_decompress_gzip(self):
        r = requests.get(httpbin('gzip'))
        r.content.decode('ascii')

    def test_unicode_get(self):
        url = httpbin('/get')
        requests.get(url, params={'foo': 'føø'})
        requests.get(url, params={'føø': 'føø'})
        requests.get(url, params={'føø': 'føø'})
        requests.get(url, params={'foo': 'foo'})
        requests.get(httpbin('ø'), params={'foo': 'foo'})

    def test_urlencoded_get_query_multivalued_param(self):

        r = requests.get(httpbin('get'), params=dict(test=['foo', 'baz']))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.url, httpbin('get?test=foo&test=baz'))

    def test_different_encodings_dont_break_post(self):
        r = requests.post(httpbin('post'),
                          data={'stuff': json.dumps({'a': 123})},
                          params={'blah': 'asdf1234'},
                          files={'file': ('test_requests.py', open(__file__, 'rb'))})
        self.assertEqual(r.status_code, 200)

    def test_custom_content_type(self):
        r = requests.post(httpbin('post'),
                          data={'stuff': json.dumps({'a': 123})},
                          files={'file1': ('test_requests.py', open(__file__, 'rb')),
                                 'file2': ('test_requests', open(__file__, 'rb'),
                                           'text/py-content-type')})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(b"text/py-content-type" in r.request.body)


if __name__ == '__main__':
    unittest.main()
