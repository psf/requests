#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for Requests."""

import json
import os
import unittest

import requests
from requests.auth import HTTPDigestAuth

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

    def test_HTTP_302_ALLOW_REDIRECT_POST(self):
        r = requests.post(httpbin('status', '302'), data={'some': 'data'})
        self.assertEqual(r.status_code, 200)

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

    def test_dataurl(self):
        r = requests.get('data:text/html;charset=utf-8,f%C3%B8%C3%B8')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get('content-type'), 'text/html;charset=utf-8')
        self.assertEqual(r.text, u'føø')
        r = requests.get('data:image/gif;base64,R0lGODdhMAAwAPAAAAAAAP///ywAAAAAMAAwAAAC8IyPqcvt3wCcDkiLc7C0qwyGHhSWpjQu5yqmCYsapyuvUUlvONmOZtfzgFzByTB10QgxOR0TqBQejhRNzOfkVJ+5YiUqrXF5Y5lKh/DeuNcP5yLWGsEbtLiOSpa/TPg7JpJHxyendzWTBfX0cxOnKPjgBzi4diinWGdkF8kjdfnycQZXZeYGejmJlZeGl9i2icVqaNVailT6F5iJ90m6mvuTS4OK05M0vDk0Q4XUtwvKOzrcd3iq9uisF81M1OIcR7lEewwcLp7tuNNkM3uNna3F2JQFo97Vriy/Xl4/f1cf5VWzXyym7PHhhx4dbgYKAAA7')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get('content-type'), 'image/gif')
        self.assertEqual(r.content, 'GIF87a0\x000\x00\xf0\x00\x00\x00\x00\x00\xff\xff\xff,\x00\x00\x00\x000\x000\x00\x00\x02\xf0\x8c\x8f\xa9\xcb\xed\xdf\x00\x9c\x0eH\x8bs\xb0\xb4\xab\x0c\x86\x1e\x14\x96\xa64.\xe7*\xa6\t\x8b\x1a\xa7+\xafQIo8\xd9\x8ef\xd7\xf3\x80\\\xc1\xc90u\xd1\x0819\x1d\x13\xa8\x14\x1e\x8e\x14M\xcc\xe7\xe4T\x9f\xb9b%*\xadqyc\x99J\x87\xf0\xde\xb8\xd7\x0f\xe7"\xd6\x1a\xc1\x1b\xb4\xb8\x8eJ\x96\xbfL\xf8;&\x92G\xc7\'\xa7w5\x93\x05\xf5\xf4s\x13\xa7(\xf8\xe0\x078\xb8v(\xa7Xgd\x17\xc9#u\xf9\xf2q\x06We\xe6\x06z9\x89\x95\x97\x86\x97\xd8\xb6\x89\xc5jh\xd5Z\x8aT\xfa\x17\x98\x89\xf7I\xba\x9a\xfb\x93K\x83\x8a\xd3\x934\xbc94C\x85\xd4\xb7\x0b\xca;:\xdcwx\xaa\xf6\xe8\xac\x17\xcdL\xd4\xe2\x1cG\xb9D{\x0c\x1c.\x9e\xed\xb8\xd3d3{\x8d\x9d\xad\xc5\xd8\x94\x05\xa3\xde\xd5\xae,\xbf^^?\x7fW\x1f\xe5U\xb3_,\xa6\xec\xf1\xe1\x87\x1e\x1dn\x06\n\x00\x00;')



if __name__ == '__main__':
    unittest.main()
