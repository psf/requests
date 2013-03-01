#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for Requests."""

from __future__ import division
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

    def test_no_content_length(self):
        get_req = requests.Request('GET', httpbin('get')).prepare()
        self.assertTrue('Content-Length' not in get_req.headers)
        head_req = requests.Request('HEAD', httpbin('head')).prepare()
        self.assertTrue('Content-Length' not in head_req.headers)

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

    def test_set_cookie_on_301(self):
        s = requests.session()
        url = httpbin('cookies/set?foo=bar')
        r = s.get(url)
        self.assertTrue(s.cookies['foo'] == 'bar')

    def test_user_agent_transfers(self):

        heads = {
            'User-agent': 'Mozilla/5.0 (github.com/kennethreitz/requests)'
        }

        r = requests.get(httpbin('user-agent'), headers=heads)
        self.assertTrue(heads['User-agent'] in r.text)

        heads = {
            'user-agent': 'Mozilla/5.0 (github.com/kennethreitz/requests)'
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

    def test_DIGEST_STREAM(self):

        auth = HTTPDigestAuth('user', 'pass')
        url = httpbin('digest-auth', 'auth', 'user', 'pass')

        r = requests.get(url, auth=auth, stream=True)
        self.assertNotEqual(r.raw.read(), b'')

        r = requests.get(url, auth=auth, stream=False)
        self.assertEqual(r.raw.read(), b'')


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

    def test_unicode_header_name(self):
        requests.put(httpbin('put'), headers={str('Content-Type'): 'application/octet-stream'}, data='\xff') # compat.str is unicode.

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

    def test_prepared_request_hook(self):
        def hook(resp):
            resp.hook_working = True
            return resp

        req = requests.Request('GET', HTTPBIN, hooks={'response': hook})
        prep = req.prepare()

        s = requests.Session()
        resp = s.send(prep)

        self.assertTrue(hasattr(resp, 'hook_working'))

    def test_links(self):
        r = requests.Response()
        r.headers = {
            'cache-control': 'public, max-age=60, s-maxage=60',
            'connection': 'keep-alive',
            'content-encoding': 'gzip',
            'content-type': 'application/json; charset=utf-8',
            'date': 'Sat, 26 Jan 2013 16:47:56 GMT',
            'etag': '"6ff6a73c0e446c1f61614769e3ceb778"',
            'last-modified': 'Sat, 26 Jan 2013 16:22:39 GMT',
            'link': ('<https://api.github.com/users/kennethreitz/repos?'
                     'page=2&per_page=10>; rel="next", <https://api.github.'
                     'com/users/kennethreitz/repos?page=7&per_page=10>; '
                     ' rel="last"'),
            'server': 'GitHub.com',
            'status': '200 OK',
            'vary': 'Accept',
            'x-content-type-options': 'nosniff',
            'x-github-media-type': 'github.beta',
            'x-ratelimit-limit': '60',
            'x-ratelimit-remaining': '57'
        }
        self.assertEqual(r.links['next']['rel'], 'next')

    def test_cookie_parameters(self):
        key = 'some_cookie'
        value = 'some_value'
        secure = True
        domain = 'test.com'
        rest = {'HttpOnly': True}

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value, secure=secure, domain=domain, rest=rest)

        self.assertEqual(len(jar), 1)
        self.assertTrue('some_cookie' in jar)

        cookie = list(jar)[0]
        self.assertEqual(cookie.secure, secure)
        self.assertEqual(cookie.domain, domain)
        self.assertEqual(cookie._rest['HttpOnly'], rest['HttpOnly'])

    def test_time_elapsed_blank(self):
        r = requests.get(httpbin('get'))
        td = r.elapsed
        total_seconds = ((td.microseconds + (td.seconds + td.days * 24 * 3600)
                         * 10**6) / 10**6)
        self.assertTrue(total_seconds > 0.0)

    def test_response_is_iterable(self):
        r = requests.Response()
        io = StringIO.StringIO('abc')
        r.raw = io
        self.assertTrue(next(iter(r)))
        io.close()

    def test_get_auth_from_url(self):
        url = 'http://user:pass@complex.url.com/path?query=yes'
        self.assertEqual(('user', 'pass'),
                         requests.utils.get_auth_from_url(url))

    def test_cannot_send_unprepared_requests(self):
        r = requests.Request(url=HTTPBIN)
        self.assertRaises(ValueError, requests.Session().send, r)

    def test_can_specify_retries(self):
        # monkey patch urlopen
        from requests.packages.urllib3.poolmanager import HTTPConnectionPool
        old_urlopen = HTTPConnectionPool.urlopen

        max_retries_used = []
        def urlopen(*args, **kwargs):
            """Save what value we used for retries each time we call urlopen."""
            max_retries_used.append(kwargs.get('retries'))
            return old_urlopen(*args, **kwargs)

        HTTPConnectionPool.urlopen = urlopen

        # do the request and check that max_retries was passed through
        requests.get(httpbin('get'), max_retries=5)
        self.assertEqual(max_retries_used, [5])

        # undo monkey patch
        HTTPConnectionPool.urlopen = old_urlopen

    def test_http_error(self):
        error = requests.exceptions.HTTPError()
        self.assertEqual(error.response, None)
        response = requests.Response()
        error = requests.exceptions.HTTPError(response=response)
        self.assertEqual(error.response, response)
        error = requests.exceptions.HTTPError('message', response=response)
        self.assertEqual(str(error), 'message')
        self.assertEqual(error.response, response)


if __name__ == '__main__':
    unittest.main()
