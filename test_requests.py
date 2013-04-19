#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for Requests."""

from __future__ import division
import json
import os
import unittest
import pickle

import requests
from requests.auth import HTTPDigestAuth
from requests.adapters import HTTPAdapter
from requests.compat import str, cookielib
from requests.cookies import cookiejar_from_dict
from requests.exceptions import InvalidURL, MissingSchema
from requests.structures import CaseInsensitiveDict

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
        self.assertRaises(MissingSchema, requests.get, 'hiwpefhipowhefopw')
        self.assertRaises(InvalidURL, requests.get, 'http://')

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

    def test_mixed_case_scheme_acceptable(self):
        s = requests.Session()
        r = requests.Request('GET', 'http://httpbin.org/get')
        r = s.send(r.prepare())
        self.assertEqual(r.status_code,200)
        s = requests.Session()
        r = requests.Request('GET', 'HTTP://httpbin.org/get')
        r = s.send(r.prepare())
        self.assertEqual(r.status_code,200)
        r = requests.Request('GET', 'hTTp://httpbin.org/get')
        r = s.send(r.prepare())
        self.assertEqual(r.status_code,200)
        r = requests.Request('GET', 'HttP://httpbin.org/get')
        r = s.send(r.prepare())
        self.assertEqual(r.status_code,200)
        r = requests.Request('GET', 'https://httpbin.org/get')
        r = s.send(r.prepare())
        self.assertEqual(r.status_code,200)
        r = requests.Request('GET', 'HTTPS://httpbin.org/get')
        r = s.send(r.prepare())
        self.assertEqual(r.status_code,200)
        r = requests.Request('GET', 'hTTps://httpbin.org/get')
        r = s.send(r.prepare())
        self.assertEqual(r.status_code,200)
        r = requests.Request('GET', 'HttPs://httpbin.org/get')
        r = s.send(r.prepare())
        self.assertEqual(r.status_code,200)

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

    def test_cookie_sent_on_redirect(self):
        s = requests.session()
        s.get(httpbin('cookies/set?foo=bar'))
        r = s.get(httpbin('redirect/1'))  # redirects to httpbin('get')
        self.assertTrue("Cookie" in r.json()["headers"])

    def test_cookie_removed_on_expire(self):
        s = requests.session()
        s.get(httpbin('cookies/set?foo=bar'))
        self.assertTrue(s.cookies['foo'] == 'bar')
        s.get(
            httpbin('response-headers'),
            params={
                'Set-Cookie':
                    'foo=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT'
            }
        )
        assert 'foo' not in s.cookies

    def test_request_cookie_overrides_session_cookie(self):
        s = requests.session()
        s.cookies['foo'] = 'bar'
        r = s.get(httpbin('cookies'), cookies={'foo': 'baz'})
        assert r.json()['cookies']['foo'] == 'baz'
        # Session cookie should not be modified
        assert s.cookies['foo'] == 'bar'

    def test_generic_cookiejar_works(self):
        cj = cookielib.CookieJar()
        cookiejar_from_dict({'foo': 'bar'}, cj)
        s = requests.session()
        s.cookies = cj
        r = s.get(httpbin('cookies'))
        # Make sure the cookie was sent
        assert r.json()['cookies']['foo'] == 'bar'
        # Make sure the session cj is still the custom one
        assert s.cookies is cj
    
    def test_requests_in_history_are_not_overridden(self):
        resp = requests.get(httpbin('redirect/3'))
        urls = [r.url for r in resp.history]
        req_urls = [r.request.url for r in resp.history]
        self.assertEquals(urls, req_urls)
        
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

    def test_unicode_multipart_post(self):
        r = requests.post(httpbin('post'),
                          data={'stuff': u'ëlïxr'},
                          files={'file': ('test_requests.py', open(__file__, 'rb'))})
        self.assertEqual(r.status_code, 200)

        r = requests.post(httpbin('post'),
                          data={'stuff': u'ëlïxr'.encode('utf-8')},
                          files={'file': ('test_requests.py', open(__file__, 'rb'))})
        self.assertEqual(r.status_code, 200)

        r = requests.post(httpbin('post'),
                          data={'stuff': 'elixr'},
                          files={'file': ('test_requests.py', open(__file__, 'rb'))})
        self.assertEqual(r.status_code, 200)

        r = requests.post(httpbin('post'),
                          data={'stuff': 'elixr'.encode('utf-8')},
                          files={'file': ('test_requests.py', open(__file__, 'rb'))})
        self.assertEqual(r.status_code, 200)

    def test_unicode_multipart_post_fieldnames(self):
        filename = os.path.splitext(__file__)[0] + '.py'
        r = requests.Request(method='POST',
                             url=httpbin('post'),
                             data={'stuff'.encode('utf-8'): 'elixr'},
                             files={'file': ('test_requests.py',
                                             open(filename, 'rb'))})
        prep = r.prepare()
        self.assertTrue(b'name="stuff"' in prep.body)
        self.assertFalse(b'name="b\'stuff\'"' in prep.body)

    def test_custom_content_type(self):
        r = requests.post(httpbin('post'),
                          data={'stuff': json.dumps({'a': 123})},
                          files={'file1': ('test_requests.py', open(__file__, 'rb')),
                                 'file2': ('test_requests', open(__file__, 'rb'),
                                           'text/py-content-type')})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(b"text/py-content-type" in r.request.body)

    def test_hook_receives_request_arguments(self):
        def hook(resp, **kwargs):
            assert resp is not None
            assert kwargs != {}

        requests.Request('GET', HTTPBIN, hooks={'response': hook})

    def test_prepared_request_hook(self):
        def hook(resp, **kwargs):
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
        read_ = io.read

        def read_mock(amt, decode_content=None):
            return read_(amt)
        setattr(io, 'read', read_mock)
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

    def test_http_error(self):
        error = requests.exceptions.HTTPError()
        self.assertEqual(error.response, None)
        response = requests.Response()
        error = requests.exceptions.HTTPError(response=response)
        self.assertEqual(error.response, response)
        error = requests.exceptions.HTTPError('message', response=response)
        self.assertEqual(str(error), 'message')
        self.assertEqual(error.response, response)

    def test_session_pickling(self):
        r = requests.Request('GET', httpbin('get'))
        s = requests.Session()

        s = pickle.loads(pickle.dumps(s))

        r = s.send(r.prepare())
        self.assertEqual(r.status_code, 200)

    def test_fixes_1329(self):
        """
        Ensure that header updates are done case-insensitively.
        """
        s = requests.Session()
        s.headers.update({'ACCEPT': 'BOGUS'})
        s.headers.update({'accept': 'application/json'})
        r = s.get(httpbin('get'))
        headers = r.request.headers
        # ASCII encode because of key comparison changes in py3
        self.assertEqual(
            headers['accept'.encode('ascii')],
            'application/json'
        )
        self.assertEqual(
            headers['Accept'.encode('ascii')],
            'application/json'
        )
        self.assertEqual(
            headers['ACCEPT'.encode('ascii')],
            'application/json'
        )

    def test_uppercase_scheme(self):
        r = requests.get('HTTP://example.com/')
        self.assertEqual(r.status_code, 200)

    def test_uppercase_scheme_redirect(self):
        r = requests.get(httpbin('redirect-to'), params={'url': 'HTTP://example.com/'})
        self.assertEqual(r.status_code, 200)

    def test_transport_adapter_ordering(self):
        s = requests.Session()
        order = ['https://', 'http://']
        self.assertEqual(order, list(s.adapters))
        s.mount('http://git', HTTPAdapter())
        s.mount('http://github', HTTPAdapter())
        s.mount('http://github.com', HTTPAdapter())
        s.mount('http://github.com/about/', HTTPAdapter())
        order = [
            'http://github.com/about/',
            'http://github.com',
            'http://github',
            'http://git',
            'https://',
            'http://',
        ]
        self.assertEqual(order, list(s.adapters))
        s.mount('http://gittip', HTTPAdapter())
        s.mount('http://gittip.com', HTTPAdapter())
        s.mount('http://gittip.com/about/', HTTPAdapter())
        order = [
            'http://github.com/about/',
            'http://gittip.com/about/',
            'http://github.com',
            'http://gittip.com',
            'http://github',
            'http://gittip',
            'http://git',
            'https://',
            'http://',
        ]
        self.assertEqual(order, list(s.adapters))
        s2 = requests.Session()
        s2.adapters = {'http://': HTTPAdapter()}
        s2.mount('https://', HTTPAdapter())
        self.assertTrue('http://' in s2.adapters)
        self.assertTrue('https://' in s2.adapters)

    def test_header_remove_is_case_insensitive(self):
        # From issue #1321
        s = requests.Session()
        s.headers['foo'] = 'bar'
        r = s.get(httpbin('get'), headers={'FOO': None})
        assert 'foo' not in r.request.headers

    def test_params_are_merged_case_sensitive(self):
        s = requests.Session()
        s.params['foo'] = 'bar'
        r = s.get(httpbin('get'), params={'FOO': 'bar'})
        assert r.json()['args'] == {'foo': 'bar', 'FOO': 'bar'}


    def test_long_authinfo_in_url(self):
        url = 'http://{0}:{1}@{2}:9000/path?query#frag'.format(
            'E8A3BE87-9E3F-4620-8858-95478E385B5B',
            'EA770032-DA4D-4D84-8CE9-29C6D910BF1E',
            'exactly-------------sixty-----------three------------characters',
        )
        r = requests.Request('GET', url).prepare()
        self.assertEqual(r.url, url)


class TestCaseInsensitiveDict(unittest.TestCase):

    def test_mapping_init(self):
        cid = CaseInsensitiveDict({'Foo': 'foo','BAr': 'bar'})
        self.assertEqual(len(cid), 2)
        self.assertTrue('foo' in cid)
        self.assertTrue('bar' in cid)

    def test_iterable_init(self):
        cid = CaseInsensitiveDict([('Foo', 'foo'), ('BAr', 'bar')])
        self.assertEqual(len(cid), 2)
        self.assertTrue('foo' in cid)
        self.assertTrue('bar' in cid)

    def test_kwargs_init(self):
        cid = CaseInsensitiveDict(FOO='foo', BAr='bar')
        self.assertEqual(len(cid), 2)
        self.assertTrue('foo' in cid)
        self.assertTrue('bar' in cid)

    def test_docstring_example(self):
        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        self.assertEqual(cid['aCCEPT'], 'application/json')
        self.assertEqual(list(cid), ['Accept'])

    def test_len(self):
        cid = CaseInsensitiveDict({'a': 'a', 'b': 'b'})
        cid['A'] = 'a'
        self.assertEqual(len(cid), 2)

    def test_getitem(self):
        cid = CaseInsensitiveDict({'Spam': 'blueval'})
        self.assertEqual(cid['spam'], 'blueval')
        self.assertEqual(cid['SPAM'], 'blueval')

    def test_fixes_649(self):
        """__setitem__ should behave case-insensitively."""
        cid = CaseInsensitiveDict()
        cid['spam'] = 'oneval'
        cid['Spam'] = 'twoval'
        cid['sPAM'] = 'redval'
        cid['SPAM'] = 'blueval'
        self.assertEqual(cid['spam'], 'blueval')
        self.assertEqual(cid['SPAM'], 'blueval')
        self.assertEqual(list(cid.keys()), ['SPAM'])

    def test_delitem(self):
        cid = CaseInsensitiveDict()
        cid['Spam'] = 'someval'
        del cid['sPam']
        self.assertFalse('spam' in cid)
        self.assertEqual(len(cid), 0)

    def test_contains(self):
        cid = CaseInsensitiveDict()
        cid['Spam'] = 'someval'
        self.assertTrue('Spam' in cid)
        self.assertTrue('spam' in cid)
        self.assertTrue('SPAM' in cid)
        self.assertTrue('sPam' in cid)
        self.assertFalse('notspam' in cid)

    def test_get(self):
        cid = CaseInsensitiveDict()
        cid['spam'] = 'oneval'
        cid['SPAM'] = 'blueval'
        self.assertEqual(cid.get('spam'), 'blueval')
        self.assertEqual(cid.get('SPAM'), 'blueval')
        self.assertEqual(cid.get('sPam'), 'blueval')
        self.assertEqual(cid.get('notspam', 'default'), 'default')

    def test_update(self):
        cid = CaseInsensitiveDict()
        cid['spam'] = 'blueval'
        cid.update({'sPam': 'notblueval'})
        self.assertEqual(cid['spam'], 'notblueval')
        cid = CaseInsensitiveDict({'Foo': 'foo','BAr': 'bar'})
        cid.update({'fOO': 'anotherfoo', 'bAR': 'anotherbar'})
        self.assertEqual(len(cid), 2)
        self.assertEqual(cid['foo'], 'anotherfoo')
        self.assertEqual(cid['bar'], 'anotherbar')

    def test_update_retains_unchanged(self):
        cid = CaseInsensitiveDict({'foo': 'foo', 'bar': 'bar'})
        cid.update({'foo': 'newfoo'})
        self.assertEquals(cid['bar'], 'bar')

    def test_iter(self):
        cid = CaseInsensitiveDict({'Spam': 'spam', 'Eggs': 'eggs'})
        keys = frozenset(['Spam', 'Eggs'])
        self.assertEqual(frozenset(iter(cid)), keys)

    def test_equality(self):
        cid = CaseInsensitiveDict({'SPAM': 'blueval', 'Eggs': 'redval'})
        othercid = CaseInsensitiveDict({'spam': 'blueval', 'eggs': 'redval'})
        self.assertEqual(cid, othercid)
        del othercid['spam']
        self.assertNotEqual(cid, othercid)
        self.assertEqual(cid, {'spam': 'blueval', 'eggs': 'redval'})

    def test_setdefault(self):
        cid = CaseInsensitiveDict({'Spam': 'blueval'})
        self.assertEqual(
            cid.setdefault('spam', 'notblueval'),
            'blueval'
        )
        self.assertEqual(
            cid.setdefault('notspam', 'notblueval'),
            'notblueval'
        )

    def test_lower_items(self):
        cid = CaseInsensitiveDict({
            'Accept': 'application/json',
            'user-Agent': 'requests',
        })
        keyset = frozenset(lowerkey for lowerkey, v in cid.lower_items())
        lowerkeyset = frozenset(['accept', 'user-agent'])
        self.assertEqual(keyset, lowerkeyset)

    def test_preserve_key_case(self):
        cid = CaseInsensitiveDict({
            'Accept': 'application/json',
            'user-Agent': 'requests',
        })
        keyset = frozenset(['Accept', 'user-Agent'])
        self.assertEqual(frozenset(i[0] for i in cid.items()), keyset)
        self.assertEqual(frozenset(cid.keys()), keyset)
        self.assertEqual(frozenset(cid), keyset)

    def test_preserve_last_key_case(self):
        cid = CaseInsensitiveDict({
            'Accept': 'application/json',
            'user-Agent': 'requests',
        })
        cid.update({'ACCEPT': 'application/json'})
        cid['USER-AGENT'] = 'requests'
        keyset = frozenset(['ACCEPT', 'USER-AGENT'])
        self.assertEqual(frozenset(i[0] for i in cid.items()), keyset)
        self.assertEqual(frozenset(cid.keys()), keyset)
        self.assertEqual(frozenset(cid), keyset)


if __name__ == '__main__':
    unittest.main()
