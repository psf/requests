#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for Requests."""

from __future__ import division
import json
import os
import pickle
import unittest
import collections

import requests
import pytest
from requests.adapters import HTTPAdapter
from requests.auth import HTTPDigestAuth
from requests.compat import (
    Morsel, cookielib, getproxies, str, urljoin, urlparse)
from requests.cookies import cookiejar_from_dict, morsel_to_cookie
from requests.exceptions import InvalidURL, MissingSchema
from requests.models import PreparedRequest, Response
from requests.structures import CaseInsensitiveDict
from requests.sessions import SessionRedirectMixin
from requests.models import PreparedRequest, urlencode
from requests.hooks import default_hooks

try:
    import StringIO
except ImportError:
    import io as StringIO

HTTPBIN = os.environ.get('HTTPBIN_URL', 'http://httpbin.org/')
# Issue #1483: Make sure the URL always has a trailing slash
HTTPBIN = HTTPBIN.rstrip('/') + '/'


def httpbin(*suffix):
    """Returns url for HTTPBIN resource."""
    return urljoin(HTTPBIN, '/'.join(suffix))


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
        with pytest.raises(MissingSchema):
            requests.get('hiwpefhipowhefopw')
        with pytest.raises(InvalidURL):
            requests.get('http://')

    def test_basic_building(self):
        req = requests.Request()
        req.url = 'http://kennethreitz.org/'
        req.data = {'life': '42'}

        pr = req.prepare()
        assert pr.url == req.url
        assert pr.body == 'life=42'

    def test_no_content_length(self):
        get_req = requests.Request('GET', httpbin('get')).prepare()
        assert 'Content-Length' not in get_req.headers
        head_req = requests.Request('HEAD', httpbin('head')).prepare()
        assert 'Content-Length' not in head_req.headers

    def test_path_is_not_double_encoded(self):
        request = requests.Request('GET', "http://0.0.0.0/get/test case").prepare()

        assert request.path_url == '/get/test%20case'

    def test_params_are_added_before_fragment(self):
        request = requests.Request('GET',
            "http://example.com/path#fragment", params={"a": "b"}).prepare()
        assert request.url == "http://example.com/path?a=b#fragment"
        request = requests.Request('GET',
            "http://example.com/path?key=value#fragment", params={"a": "b"}).prepare()
        assert request.url == "http://example.com/path?key=value&a=b#fragment"

    def test_mixed_case_scheme_acceptable(self):
        s = requests.Session()
        s.proxies = getproxies()
        parts = urlparse(httpbin('get'))
        schemes = ['http://', 'HTTP://', 'hTTp://', 'HttP://',
                   'https://', 'HTTPS://', 'hTTps://', 'HttPs://']
        for scheme in schemes:
            url = scheme + parts.netloc + parts.path
            r = requests.Request('GET', url)
            r = s.send(r.prepare())
            assert r.status_code == 200, 'failed for scheme {0}'.format(scheme)

    def test_HTTP_200_OK_GET_ALTERNATIVE(self):
        r = requests.Request('GET', httpbin('get'))
        s = requests.Session()
        s.proxies = getproxies()

        r = s.send(r.prepare())

        assert r.status_code == 200

    def test_HTTP_302_ALLOW_REDIRECT_GET(self):
        r = requests.get(httpbin('redirect', '1'))
        assert r.status_code == 200
        assert r.history[0].status_code == 302
        assert r.history[0].is_redirect

    # def test_HTTP_302_ALLOW_REDIRECT_POST(self):
    #     r = requests.post(httpbin('status', '302'), data={'some': 'data'})
    #     self.assertEqual(r.status_code, 200)

    def test_HTTP_200_OK_GET_WITH_PARAMS(self):
        heads = {'User-agent': 'Mozilla/5.0'}

        r = requests.get(httpbin('user-agent'), headers=heads)

        assert heads['User-agent'] in r.text
        assert r.status_code == 200

    def test_HTTP_200_OK_GET_WITH_MIXED_PARAMS(self):
        heads = {'User-agent': 'Mozilla/5.0'}

        r = requests.get(httpbin('get') + '?test=true', params={'q': 'test'}, headers=heads)
        assert r.status_code == 200

    def test_set_cookie_on_301(self):
        s = requests.session()
        url = httpbin('cookies/set?foo=bar')
        r = s.get(url)
        assert s.cookies['foo'] == 'bar'

    def test_cookie_sent_on_redirect(self):
        s = requests.session()
        s.get(httpbin('cookies/set?foo=bar'))
        r = s.get(httpbin('redirect/1'))  # redirects to httpbin('get')
        assert 'Cookie' in r.json()['headers']

    def test_cookie_removed_on_expire(self):
        s = requests.session()
        s.get(httpbin('cookies/set?foo=bar'))
        assert s.cookies['foo'] == 'bar'
        s.get(
            httpbin('response-headers'),
            params={
                'Set-Cookie':
                    'foo=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT'
            }
        )
        assert 'foo' not in s.cookies

    def test_cookie_quote_wrapped(self):
        s = requests.session()
        s.get(httpbin('cookies/set?foo="bar:baz"'))
        assert s.cookies['foo'] == '"bar:baz"'

    def test_cookie_persists_via_api(self):
        s = requests.session()
        r = s.get(httpbin('redirect/1'), cookies={'foo': 'bar'})
        assert 'foo' in r.request.headers['Cookie']
        assert 'foo' in r.history[0].request.headers['Cookie']

    def test_request_cookie_overrides_session_cookie(self):
        s = requests.session()
        s.cookies['foo'] = 'bar'
        r = s.get(httpbin('cookies'), cookies={'foo': 'baz'})
        assert r.json()['cookies']['foo'] == 'baz'
        # Session cookie should not be modified
        assert s.cookies['foo'] == 'bar'

    def test_request_cookies_not_persisted(self):
        s = requests.session()
        s.get(httpbin('cookies'), cookies={'foo': 'baz'})
        # Sending a request with cookies should not add cookies to the session
        assert not s.cookies

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

    def test_param_cookiejar_works(self):
        cj = cookielib.CookieJar()
        cookiejar_from_dict({'foo' : 'bar'}, cj)
        s = requests.session()
        r = s.get(httpbin('cookies'), cookies=cj)
        # Make sure the cookie was sent
        assert r.json()['cookies']['foo'] == 'bar'

    def test_requests_in_history_are_not_overridden(self):
        resp = requests.get(httpbin('redirect/3'))
        urls = [r.url for r in resp.history]
        req_urls = [r.request.url for r in resp.history]
        assert urls == req_urls

    def test_history_is_always_a_list(self):
        """
        Show that even with redirects, Response.history is always a list.
        """
        resp = requests.get(httpbin('get'))
        assert isinstance(resp.history, list)
        resp = requests.get(httpbin('redirect/1'))
        assert isinstance(resp.history, list)
        assert not isinstance(resp.history, tuple)

    def test_headers_on_session_with_None_are_not_sent(self):
        """Do not send headers in Session.headers with None values."""
        ses = requests.Session()
        ses.headers['Accept-Encoding'] = None
        req = requests.Request('GET', 'http://httpbin.org/get')
        prep = ses.prepare_request(req)
        assert 'Accept-Encoding' not in prep.headers

    def test_user_agent_transfers(self):

        heads = {
            'User-agent': 'Mozilla/5.0 (github.com/kennethreitz/requests)'
        }

        r = requests.get(httpbin('user-agent'), headers=heads)
        assert heads['User-agent'] in r.text

        heads = {
            'user-agent': 'Mozilla/5.0 (github.com/kennethreitz/requests)'
        }

        r = requests.get(httpbin('user-agent'), headers=heads)
        assert heads['user-agent'] in r.text

    def test_HTTP_200_OK_HEAD(self):
        r = requests.head(httpbin('get'))
        assert r.status_code == 200

    def test_HTTP_200_OK_PUT(self):
        r = requests.put(httpbin('put'))
        assert r.status_code == 200

    def test_BASICAUTH_TUPLE_HTTP_200_OK_GET(self):
        auth = ('user', 'pass')
        url = httpbin('basic-auth', 'user', 'pass')

        r = requests.get(url, auth=auth)
        assert r.status_code == 200

        r = requests.get(url)
        assert r.status_code == 401

        s = requests.session()
        s.auth = auth
        r = s.get(url)
        assert r.status_code == 200

    def test_basicauth_with_netrc(self):
        auth = ('user', 'pass')
        wrong_auth = ('wronguser', 'wrongpass')
        url = httpbin('basic-auth', 'user', 'pass')

        def get_netrc_auth_mock(url):
            return auth
        requests.sessions.get_netrc_auth = get_netrc_auth_mock

        # Should use netrc and work.
        r = requests.get(url)
        assert r.status_code == 200

        # Given auth should override and fail.
        r = requests.get(url, auth=wrong_auth)
        assert r.status_code == 401

        s = requests.session()

        # Should use netrc and work.
        r = s.get(url)
        assert r.status_code == 200

        # Given auth should override and fail.
        s.auth = wrong_auth
        r = s.get(url)
        assert r.status_code == 401

    def test_DIGEST_HTTP_200_OK_GET(self):

        auth = HTTPDigestAuth('user', 'pass')
        url = httpbin('digest-auth', 'auth', 'user', 'pass')

        r = requests.get(url, auth=auth)
        assert r.status_code == 200

        r = requests.get(url)
        assert r.status_code == 401

        s = requests.session()
        s.auth = HTTPDigestAuth('user', 'pass')
        r = s.get(url)
        assert r.status_code == 200

    def test_DIGEST_AUTH_RETURNS_COOKIE(self):
        url = httpbin('digest-auth', 'auth', 'user', 'pass')
        auth = HTTPDigestAuth('user', 'pass')
        r = requests.get(url)
        assert r.cookies['fake'] == 'fake_value'

        r = requests.get(url, auth=auth)
        assert r.status_code == 200

    def test_DIGEST_AUTH_SETS_SESSION_COOKIES(self):
        url = httpbin('digest-auth', 'auth', 'user', 'pass')
        auth = HTTPDigestAuth('user', 'pass')
        s = requests.Session()
        s.get(url, auth=auth)
        assert s.cookies['fake'] == 'fake_value'

    def test_DIGEST_STREAM(self):

        auth = HTTPDigestAuth('user', 'pass')
        url = httpbin('digest-auth', 'auth', 'user', 'pass')

        r = requests.get(url, auth=auth, stream=True)
        assert r.raw.read() != b''

        r = requests.get(url, auth=auth, stream=False)
        assert r.raw.read() == b''

    def test_DIGESTAUTH_WRONG_HTTP_401_GET(self):

        auth = HTTPDigestAuth('user', 'wrongpass')
        url = httpbin('digest-auth', 'auth', 'user', 'pass')

        r = requests.get(url, auth=auth)
        assert r.status_code == 401

        r = requests.get(url)
        assert r.status_code == 401

        s = requests.session()
        s.auth = auth
        r = s.get(url)
        assert r.status_code == 401

    def test_DIGESTAUTH_QUOTES_QOP_VALUE(self):

        auth = HTTPDigestAuth('user', 'pass')
        url = httpbin('digest-auth', 'auth', 'user', 'pass')

        r = requests.get(url, auth=auth)
        assert '"auth"' in r.request.headers['Authorization']

    def test_POSTBIN_GET_POST_FILES(self):

        url = httpbin('post')
        post1 = requests.post(url).raise_for_status()

        post1 = requests.post(url, data={'some': 'data'})
        assert post1.status_code == 200

        with open('requirements.txt') as f:
            post2 = requests.post(url, files={'some': f})
        assert post2.status_code == 200

        post4 = requests.post(url, data='[{"some": "json"}]')
        assert post4.status_code == 200

        with pytest.raises(ValueError):
            requests.post(url, files = ['bad file data'])

    def test_POSTBIN_GET_POST_FILES_WITH_DATA(self):

        url = httpbin('post')
        post1 = requests.post(url).raise_for_status()

        post1 = requests.post(url, data={'some': 'data'})
        assert post1.status_code == 200

        with open('requirements.txt') as f:
            post2 = requests.post(url, data={'some': 'data'}, files={'some': f})
        assert post2.status_code == 200

        post4 = requests.post(url, data='[{"some": "json"}]')
        assert post4.status_code == 200

        with pytest.raises(ValueError):
            requests.post(url, files = ['bad file data'])

    def test_conflicting_post_params(self):
        url = httpbin('post')
        with open('requirements.txt') as f:
            pytest.raises(ValueError, "requests.post(url, data='[{\"some\": \"data\"}]', files={'some': f})")
            pytest.raises(ValueError, "requests.post(url, data=u'[{\"some\": \"data\"}]', files={'some': f})")

    def test_request_ok_set(self):
        r = requests.get(httpbin('status', '404'))
        assert not r.ok

    def test_status_raising(self):
        r = requests.get(httpbin('status', '404'))
        with pytest.raises(requests.exceptions.HTTPError):
            r.raise_for_status()

        r = requests.get(httpbin('status', '500'))
        assert not r.ok

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

    def test_pyopenssl_redirect(self):
        requests.get('https://httpbin.org/status/301')

    def test_urlencoded_get_query_multivalued_param(self):

        r = requests.get(httpbin('get'), params=dict(test=['foo', 'baz']))
        assert r.status_code == 200
        assert r.url == httpbin('get?test=foo&test=baz')

    def test_different_encodings_dont_break_post(self):
        r = requests.post(httpbin('post'),
                          data={'stuff': json.dumps({'a': 123})},
                          params={'blah': 'asdf1234'},
                          files={'file': ('test_requests.py', open(__file__, 'rb'))})
        assert r.status_code == 200

    def test_unicode_multipart_post(self):
        r = requests.post(httpbin('post'),
                          data={'stuff': u'ëlïxr'},
                          files={'file': ('test_requests.py', open(__file__, 'rb'))})
        assert r.status_code == 200

        r = requests.post(httpbin('post'),
                          data={'stuff': u'ëlïxr'.encode('utf-8')},
                          files={'file': ('test_requests.py', open(__file__, 'rb'))})
        assert r.status_code == 200

        r = requests.post(httpbin('post'),
                          data={'stuff': 'elixr'},
                          files={'file': ('test_requests.py', open(__file__, 'rb'))})
        assert r.status_code == 200

        r = requests.post(httpbin('post'),
                          data={'stuff': 'elixr'.encode('utf-8')},
                          files={'file': ('test_requests.py', open(__file__, 'rb'))})
        assert r.status_code == 200

    def test_unicode_multipart_post_fieldnames(self):
        filename = os.path.splitext(__file__)[0] + '.py'
        r = requests.Request(method='POST',
                             url=httpbin('post'),
                             data={'stuff'.encode('utf-8'): 'elixr'},
                             files={'file': ('test_requests.py',
                                             open(filename, 'rb'))})
        prep = r.prepare()
        assert b'name="stuff"' in prep.body
        assert b'name="b\'stuff\'"' not in prep.body

    def test_unicode_method_name(self):
        files = {'file': open('test_requests.py', 'rb')}
        r = requests.request(method=u'POST', url=httpbin('post'), files=files)
        assert r.status_code == 200

    def test_custom_content_type(self):
        r = requests.post(httpbin('post'),
                          data={'stuff': json.dumps({'a': 123})},
                          files={'file1': ('test_requests.py', open(__file__, 'rb')),
                                 'file2': ('test_requests', open(__file__, 'rb'),
                                           'text/py-content-type')})
        assert r.status_code == 200
        assert b"text/py-content-type" in r.request.body

    def test_hook_receives_request_arguments(self):
        def hook(resp, **kwargs):
            assert resp is not None
            assert kwargs != {}

        requests.Request('GET', HTTPBIN, hooks={'response': hook})

    def test_session_hooks_are_used_with_no_request_hooks(self):
        hook = lambda x, *args, **kwargs: x
        s = requests.Session()
        s.hooks['response'].append(hook)
        r = requests.Request('GET', HTTPBIN)
        prep = s.prepare_request(r)
        assert prep.hooks['response'] != []
        assert prep.hooks['response'] == [hook]

    def test_session_hooks_are_overriden_by_request_hooks(self):
        hook1 = lambda x, *args, **kwargs: x
        hook2 = lambda x, *args, **kwargs: x
        assert hook1 is not hook2
        s = requests.Session()
        s.hooks['response'].append(hook2)
        r = requests.Request('GET', HTTPBIN, hooks={'response': [hook1]})
        prep = s.prepare_request(r)
        assert prep.hooks['response'] == [hook1]

    def test_prepared_request_hook(self):
        def hook(resp, **kwargs):
            resp.hook_working = True
            return resp

        req = requests.Request('GET', HTTPBIN, hooks={'response': hook})
        prep = req.prepare()

        s = requests.Session()
        s.proxies = getproxies()
        resp = s.send(prep)

        assert hasattr(resp, 'hook_working')

    def test_prepared_from_session(self):
        class DummyAuth(requests.auth.AuthBase):
            def __call__(self, r):
                r.headers['Dummy-Auth-Test'] = 'dummy-auth-test-ok'
                return r

        req = requests.Request('GET', httpbin('headers'))
        assert not req.auth

        s = requests.Session()
        s.auth = DummyAuth()

        prep = s.prepare_request(req)
        resp = s.send(prep)

        assert resp.json()['headers']['Dummy-Auth-Test'] == 'dummy-auth-test-ok'

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
        assert r.links['next']['rel'] == 'next'

    def test_cookie_parameters(self):
        key = 'some_cookie'
        value = 'some_value'
        secure = True
        domain = 'test.com'
        rest = {'HttpOnly': True}

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value, secure=secure, domain=domain, rest=rest)

        assert len(jar) == 1
        assert 'some_cookie' in jar

        cookie = list(jar)[0]
        assert cookie.secure == secure
        assert cookie.domain == domain
        assert cookie._rest['HttpOnly'] == rest['HttpOnly']

    def test_cookie_as_dict_keeps_len(self):
        key = 'some_cookie'
        value = 'some_value'

        key1 = 'some_cookie1'
        value1 = 'some_value1'

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        d1 = dict(jar)
        d2 = dict(jar.iteritems())
        d3 = dict(jar.items())

        assert len(jar) == 2
        assert len(d1) == 2
        assert len(d2) == 2
        assert len(d3) == 2

    def test_cookie_as_dict_keeps_items(self):
        key = 'some_cookie'
        value = 'some_value'

        key1 = 'some_cookie1'
        value1 = 'some_value1'

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        d1 = dict(jar)
        d2 = dict(jar.iteritems())
        d3 = dict(jar.items())

        assert d1['some_cookie'] == 'some_value'
        assert d2['some_cookie'] == 'some_value'
        assert d3['some_cookie1'] == 'some_value1'

    def test_cookie_as_dict_keys(self):
        key = 'some_cookie'
        value = 'some_value'

        key1 = 'some_cookie1'
        value1 = 'some_value1'

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        keys = jar.keys()
        assert keys == list(keys)
        # make sure one can use keys multiple times
        assert list(keys) == list(keys)

    def test_cookie_as_dict_values(self):
        key = 'some_cookie'
        value = 'some_value'

        key1 = 'some_cookie1'
        value1 = 'some_value1'

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        values = jar.values()
        assert values == list(values)
        # make sure one can use values multiple times
        assert list(values) == list(values)

    def test_cookie_as_dict_items(self):
        key = 'some_cookie'
        value = 'some_value'

        key1 = 'some_cookie1'
        value1 = 'some_value1'

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        items = jar.items()
        assert items == list(items)
        # make sure one can use items multiple times
        assert list(items) == list(items)


    def test_time_elapsed_blank(self):
        r = requests.get(httpbin('get'))
        td = r.elapsed
        total_seconds = ((td.microseconds + (td.seconds + td.days * 24 * 3600)
                         * 10**6) / 10**6)
        assert total_seconds > 0.0

    def test_response_is_iterable(self):
        r = requests.Response()
        io = StringIO.StringIO('abc')
        read_ = io.read

        def read_mock(amt, decode_content=None):
            return read_(amt)
        setattr(io, 'read', read_mock)
        r.raw = io
        assert next(iter(r))
        io.close()

    def test_request_and_response_are_pickleable(self):
        r = requests.get(httpbin('get'))

        # verify we can pickle the original request
        assert pickle.loads(pickle.dumps(r.request))

        # verify we can pickle the response and that we have access to
        # the original request.
        pr = pickle.loads(pickle.dumps(r))
        assert r.request.url == pr.request.url
        assert r.request.headers == pr.request.headers

    def test_get_auth_from_url(self):
        url = 'http://user:pass@complex.url.com/path?query=yes'
        assert ('user', 'pass') == requests.utils.get_auth_from_url(url)

    def test_get_auth_from_url_encoded_spaces(self):
        url = 'http://user:pass%20pass@complex.url.com/path?query=yes'
        assert ('user', 'pass pass') == requests.utils.get_auth_from_url(url)

    def test_get_auth_from_url_not_encoded_spaces(self):
        url = 'http://user:pass pass@complex.url.com/path?query=yes'
        assert ('user', 'pass pass') == requests.utils.get_auth_from_url(url)

    def test_get_auth_from_url_percent_chars(self):
        url = 'http://user%25user:pass@complex.url.com/path?query=yes'
        assert ('user%user', 'pass') == requests.utils.get_auth_from_url(url)

    def test_get_auth_from_url_encoded_hashes(self):
        url = 'http://user:pass%23pass@complex.url.com/path?query=yes'
        assert ('user', 'pass#pass') == requests.utils.get_auth_from_url(url)

    def test_cannot_send_unprepared_requests(self):
        r = requests.Request(url=HTTPBIN)
        with pytest.raises(ValueError):
            requests.Session().send(r)

    def test_http_error(self):
        error = requests.exceptions.HTTPError()
        assert not error.response
        response = requests.Response()
        error = requests.exceptions.HTTPError(response=response)
        assert error.response == response
        error = requests.exceptions.HTTPError('message', response=response)
        assert str(error) == 'message'
        assert error.response == response

    def test_session_pickling(self):
        r = requests.Request('GET', httpbin('get'))
        s = requests.Session()

        s = pickle.loads(pickle.dumps(s))
        s.proxies = getproxies()

        r = s.send(r.prepare())
        assert r.status_code == 200

    def test_fixes_1329(self):
        """
        Ensure that header updates are done case-insensitively.
        """
        s = requests.Session()
        s.headers.update({'ACCEPT': 'BOGUS'})
        s.headers.update({'accept': 'application/json'})
        r = s.get(httpbin('get'))
        headers = r.request.headers
        assert headers['accept'] == 'application/json'
        assert headers['Accept'] == 'application/json'
        assert headers['ACCEPT'] == 'application/json'

    def test_uppercase_scheme_redirect(self):
        parts = urlparse(httpbin('html'))
        url = "HTTP://" + parts.netloc + parts.path
        r = requests.get(httpbin('redirect-to'), params={'url': url})
        assert r.status_code == 200
        assert r.url.lower() == url.lower()

    def test_transport_adapter_ordering(self):
        s = requests.Session()
        order = ['https://', 'http://']
        assert order == list(s.adapters)
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
        assert order == list(s.adapters)
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
        assert order == list(s.adapters)
        s2 = requests.Session()
        s2.adapters = {'http://': HTTPAdapter()}
        s2.mount('https://', HTTPAdapter())
        assert 'http://' in s2.adapters
        assert 'https://' in s2.adapters

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
        assert r.url == url

    def test_header_keys_are_native(self):
        headers = {u'unicode': 'blah', 'byte'.encode('ascii'): 'blah'}
        r = requests.Request('GET', httpbin('get'), headers=headers)
        p = r.prepare()

        # This is testing that they are builtin strings. A bit weird, but there
        # we go.
        assert 'unicode' in p.headers.keys()
        assert 'byte' in p.headers.keys()

    def test_can_send_nonstring_objects_with_files(self):
        data = {'a': 0.0}
        files = {'b': 'foo'}
        r = requests.Request('POST', httpbin('post'), data=data, files=files)
        p = r.prepare()

        assert 'multipart/form-data' in p.headers['Content-Type']

    def test_autoset_header_values_are_native(self):
        data = 'this is a string'
        length = '16'
        req = requests.Request('POST', httpbin('post'), data=data)
        p = req.prepare()

        assert p.headers['Content-Length'] == length

    def test_oddball_schemes_dont_check_URLs(self):
        test_urls = (
            'data:image/gif;base64,R0lGODlhAQABAHAAACH5BAUAAAAALAAAAAABAAEAAAICRAEAOw==',
            'file:///etc/passwd',
            'magnet:?xt=urn:btih:be08f00302bc2d1d3cfa3af02024fa647a271431',
        )
        for test_url in test_urls:
            req = requests.Request('GET', test_url)
            preq = req.prepare()
            assert test_url == preq.url

    def test_auth_is_stripped_on_redirect_off_host(self):
        r = requests.get(
            httpbin('redirect-to'),
            params={'url': 'http://www.google.co.uk'},
            auth=('user', 'pass'),
        )
        assert r.history[0].request.headers['Authorization']
        assert not r.request.headers.get('Authorization', '')

    def test_auth_is_retained_for_redirect_on_host(self):
        r = requests.get(httpbin('redirect/1'), auth=('user', 'pass'))
        h1 = r.history[0].request.headers['Authorization']
        h2 = r.request.headers['Authorization']

        assert h1 == h2


class TestContentEncodingDetection(unittest.TestCase):

    def test_none(self):
        encodings = requests.utils.get_encodings_from_content('')
        assert not len(encodings)

    def test_html_charset(self):
        """HTML5 meta charset attribute"""
        content = '<meta charset="UTF-8">'
        encodings = requests.utils.get_encodings_from_content(content)
        assert len(encodings) == 1
        assert encodings[0] == 'UTF-8'

    def test_html4_pragma(self):
        """HTML4 pragma directive"""
        content = '<meta http-equiv="Content-type" content="text/html;charset=UTF-8">'
        encodings = requests.utils.get_encodings_from_content(content)
        assert len(encodings) == 1
        assert encodings[0] == 'UTF-8'

    def test_xhtml_pragma(self):
        """XHTML 1.x served with text/html MIME type"""
        content = '<meta http-equiv="Content-type" content="text/html;charset=UTF-8" />'
        encodings = requests.utils.get_encodings_from_content(content)
        assert len(encodings) == 1
        assert encodings[0] == 'UTF-8'

    def test_xml(self):
        """XHTML 1.x served as XML"""
        content = '<?xml version="1.0" encoding="UTF-8"?>'
        encodings = requests.utils.get_encodings_from_content(content)
        assert len(encodings) == 1
        assert encodings[0] == 'UTF-8'

    def test_precedence(self):
        content = '''
        <?xml version="1.0" encoding="XML"?>
        <meta charset="HTML5">
        <meta http-equiv="Content-type" content="text/html;charset=HTML4" />
        '''.strip()
        encodings = requests.utils.get_encodings_from_content(content)
        assert encodings == ['HTML5', 'HTML4', 'XML']


class TestCaseInsensitiveDict(unittest.TestCase):

    def test_mapping_init(self):
        cid = CaseInsensitiveDict({'Foo': 'foo','BAr': 'bar'})
        assert len(cid) == 2
        assert 'foo' in cid
        assert 'bar' in cid

    def test_iterable_init(self):
        cid = CaseInsensitiveDict([('Foo', 'foo'), ('BAr', 'bar')])
        assert len(cid) == 2
        assert 'foo' in cid
        assert 'bar' in cid

    def test_kwargs_init(self):
        cid = CaseInsensitiveDict(FOO='foo', BAr='bar')
        assert len(cid) == 2
        assert 'foo' in cid
        assert 'bar' in cid

    def test_docstring_example(self):
        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        assert cid['aCCEPT'] == 'application/json'
        assert list(cid) == ['Accept']

    def test_len(self):
        cid = CaseInsensitiveDict({'a': 'a', 'b': 'b'})
        cid['A'] = 'a'
        assert len(cid) == 2

    def test_getitem(self):
        cid = CaseInsensitiveDict({'Spam': 'blueval'})
        assert cid['spam'] == 'blueval'
        assert cid['SPAM'] == 'blueval'

    def test_fixes_649(self):
        """__setitem__ should behave case-insensitively."""
        cid = CaseInsensitiveDict()
        cid['spam'] = 'oneval'
        cid['Spam'] = 'twoval'
        cid['sPAM'] = 'redval'
        cid['SPAM'] = 'blueval'
        assert cid['spam'] == 'blueval'
        assert cid['SPAM'] == 'blueval'
        assert list(cid.keys()) == ['SPAM']

    def test_delitem(self):
        cid = CaseInsensitiveDict()
        cid['Spam'] = 'someval'
        del cid['sPam']
        assert 'spam' not in cid
        assert len(cid) == 0

    def test_contains(self):
        cid = CaseInsensitiveDict()
        cid['Spam'] = 'someval'
        assert 'Spam' in cid
        assert 'spam' in cid
        assert 'SPAM' in cid
        assert 'sPam' in cid
        assert 'notspam' not in cid

    def test_get(self):
        cid = CaseInsensitiveDict()
        cid['spam'] = 'oneval'
        cid['SPAM'] = 'blueval'
        assert cid.get('spam') == 'blueval'
        assert cid.get('SPAM') == 'blueval'
        assert cid.get('sPam') == 'blueval'
        assert cid.get('notspam', 'default') == 'default'

    def test_update(self):
        cid = CaseInsensitiveDict()
        cid['spam'] = 'blueval'
        cid.update({'sPam': 'notblueval'})
        assert cid['spam'] == 'notblueval'
        cid = CaseInsensitiveDict({'Foo': 'foo','BAr': 'bar'})
        cid.update({'fOO': 'anotherfoo', 'bAR': 'anotherbar'})
        assert len(cid) == 2
        assert cid['foo'] == 'anotherfoo'
        assert cid['bar'] == 'anotherbar'

    def test_update_retains_unchanged(self):
        cid = CaseInsensitiveDict({'foo': 'foo', 'bar': 'bar'})
        cid.update({'foo': 'newfoo'})
        assert cid['bar'] == 'bar'

    def test_iter(self):
        cid = CaseInsensitiveDict({'Spam': 'spam', 'Eggs': 'eggs'})
        keys = frozenset(['Spam', 'Eggs'])
        assert frozenset(iter(cid)) == keys

    def test_equality(self):
        cid = CaseInsensitiveDict({'SPAM': 'blueval', 'Eggs': 'redval'})
        othercid = CaseInsensitiveDict({'spam': 'blueval', 'eggs': 'redval'})
        assert cid == othercid
        del othercid['spam']
        assert cid != othercid
        assert cid == {'spam': 'blueval', 'eggs': 'redval'}

    def test_setdefault(self):
        cid = CaseInsensitiveDict({'Spam': 'blueval'})
        assert cid.setdefault('spam', 'notblueval') == 'blueval'
        assert cid.setdefault('notspam', 'notblueval') == 'notblueval'

    def test_lower_items(self):
        cid = CaseInsensitiveDict({
            'Accept': 'application/json',
            'user-Agent': 'requests',
        })
        keyset = frozenset(lowerkey for lowerkey, v in cid.lower_items())
        lowerkeyset = frozenset(['accept', 'user-agent'])
        assert keyset == lowerkeyset

    def test_preserve_key_case(self):
        cid = CaseInsensitiveDict({
            'Accept': 'application/json',
            'user-Agent': 'requests',
        })
        keyset = frozenset(['Accept', 'user-Agent'])
        assert frozenset(i[0] for i in cid.items()) == keyset
        assert frozenset(cid.keys()) == keyset
        assert frozenset(cid) == keyset

    def test_preserve_last_key_case(self):
        cid = CaseInsensitiveDict({
            'Accept': 'application/json',
            'user-Agent': 'requests',
        })
        cid.update({'ACCEPT': 'application/json'})
        cid['USER-AGENT'] = 'requests'
        keyset = frozenset(['ACCEPT', 'USER-AGENT'])
        assert frozenset(i[0] for i in cid.items()) == keyset
        assert frozenset(cid.keys()) == keyset
        assert frozenset(cid) == keyset


class UtilsTestCase(unittest.TestCase):

    def test_super_len_io_streams(self):
        """ Ensures that we properly deal with different kinds of IO streams. """
        # uses StringIO or io.StringIO (see import above)
        from io import BytesIO
        from requests.utils import super_len

        assert super_len(StringIO.StringIO()) == 0
        assert super_len(StringIO.StringIO('with so much drama in the LBC')) == 29

        assert super_len(BytesIO()) == 0
        assert super_len(BytesIO(b"it's kinda hard bein' snoop d-o-double-g")) == 40

        try:
            import cStringIO
        except ImportError:
            pass
        else:
            assert super_len(cStringIO.StringIO('but some how, some way...')) == 25

    def test_get_environ_proxies_ip_ranges(self):
        """ Ensures that IP addresses are correctly matches with ranges in no_proxy variable """
        from requests.utils import get_environ_proxies
        os.environ['no_proxy'] = "192.168.0.0/24,127.0.0.1,localhost.localdomain,172.16.1.1"
        assert get_environ_proxies('http://192.168.0.1:5000/') == {}
        assert get_environ_proxies('http://192.168.0.1/') == {}
        assert get_environ_proxies('http://172.16.1.1/') == {}
        assert get_environ_proxies('http://172.16.1.1:5000/') == {}
        assert get_environ_proxies('http://192.168.1.1:5000/') != {}
        assert get_environ_proxies('http://192.168.1.1/') != {}

    def test_get_environ_proxies(self):
        """ Ensures that IP addresses are correctly matches with ranges in no_proxy variable """
        from requests.utils import get_environ_proxies
        os.environ['no_proxy'] = "127.0.0.1,localhost.localdomain,192.168.0.0/24,172.16.1.1"
        assert get_environ_proxies('http://localhost.localdomain:5000/v1.0/') == {}
        assert get_environ_proxies('http://www.requests.com/') != {}

    def test_is_ipv4_address(self):
        from requests.utils import is_ipv4_address
        assert is_ipv4_address('8.8.8.8')
        assert not is_ipv4_address('8.8.8.8.8')
        assert not is_ipv4_address('localhost.localdomain')

    def test_is_valid_cidr(self):
        from requests.utils import is_valid_cidr
        assert not is_valid_cidr('8.8.8.8')
        assert is_valid_cidr('192.168.1.0/24')

    def test_dotted_netmask(self):
        from requests.utils import dotted_netmask
        assert dotted_netmask(8) == '255.0.0.0'
        assert dotted_netmask(24) == '255.255.255.0'
        assert dotted_netmask(25) == '255.255.255.128'

    def test_address_in_network(self):
        from requests.utils import address_in_network
        assert address_in_network('192.168.1.1', '192.168.1.0/24')
        assert not address_in_network('172.16.0.1', '192.168.1.0/24')

    def test_get_auth_from_url(self):
        """ Ensures that username and password in well-encoded URI as per RFC 3986 are correclty extracted """
        from requests.utils import get_auth_from_url
        from requests.compat import quote
        percent_encoding_test_chars = "%!*'();:@&=+$,/?#[] "
        url_address = "request.com/url.html#test"
        url = "http://" + quote(percent_encoding_test_chars, '') + ':' + quote(percent_encoding_test_chars, '') + '@' + url_address
        (username, password) = get_auth_from_url(url)
        assert username == percent_encoding_test_chars
        assert password == percent_encoding_test_chars


class TestMorselToCookieExpires(unittest.TestCase):

    """Tests for morsel_to_cookie when morsel contains expires."""

    def test_expires_valid_str(self):
        """Test case where we convert expires from string time."""

        morsel = Morsel()
        morsel['expires'] = 'Thu, 01-Jan-1970 00:00:01 GMT'
        cookie = morsel_to_cookie(morsel)
        assert cookie.expires == 1

    def test_expires_invalid_int(self):
        """Test case where an invalid type is passed for expires."""

        morsel = Morsel()
        morsel['expires'] = 100
        with pytest.raises(TypeError):
            morsel_to_cookie(morsel)

    def test_expires_invalid_str(self):
        """Test case where an invalid string is input."""

        morsel = Morsel()
        morsel['expires'] = 'woops'
        with pytest.raises(ValueError):
            morsel_to_cookie(morsel)

    def test_expires_none(self):
        """Test case where expires is None."""

        morsel = Morsel()
        morsel['expires'] = None
        cookie = morsel_to_cookie(morsel)
        assert cookie.expires is None


class TestMorselToCookieMaxAge(unittest.TestCase):

    """Tests for morsel_to_cookie when morsel contains max-age."""

    def test_max_age_valid_int(self):
        """Test case where a valid max age in seconds is passed."""

        morsel = Morsel()
        morsel['max-age'] = 60
        cookie = morsel_to_cookie(morsel)
        assert isinstance(cookie.expires, int)

    def test_max_age_invalid_str(self):
        """Test case where a invalid max age is passed."""

        morsel = Morsel()
        morsel['max-age'] = 'woops'
        with pytest.raises(TypeError):
            morsel_to_cookie(morsel)


class TestTimeout:
    def test_stream_timeout(self):
        try:
            r = requests.get('https://httpbin.org/delay/10', timeout=5.0)
        except requests.exceptions.Timeout as e:
            assert 'Read timed out' in e.args[0].args[0]


SendCall = collections.namedtuple('SendCall', ('args', 'kwargs'))


class RedirectSession(SessionRedirectMixin):
    def __init__(self, order_of_redirects):
        self.redirects = order_of_redirects
        self.calls = []
        self.max_redirects = 30
        self.cookies = {}
        self.trust_env = False

    def send(self, *args, **kwargs):
        self.calls.append(SendCall(args, kwargs))
        return self.build_response()

    def build_response(self):
        request = self.calls[-1].args[0]
        r = requests.Response()

        try:
            r.status_code = int(self.redirects.pop(0))
        except IndexError:
            r.status_code = 200

        r.headers = CaseInsensitiveDict({'Location': '/'})
        r.raw = self._build_raw()
        r.request = request
        return r

    def _build_raw(self):
        string = StringIO.StringIO('')
        setattr(string, 'release_conn', lambda *args: args)
        return string


class TestRedirects:
    default_keyword_args = {
        'stream': False,
        'verify': True,
        'cert': None,
        'timeout': None,
        'allow_redirects': False,
        'proxies': {},
    }

    def test_requests_are_updated_each_time(self):
        session = RedirectSession([303, 307])
        prep = requests.Request('POST', 'http://httpbin.org/post').prepare()
        r0 = session.send(prep)
        assert r0.request.method == 'POST'
        assert session.calls[-1] == SendCall((r0.request,), {})
        redirect_generator = session.resolve_redirects(r0, prep)
        for response in redirect_generator:
            assert response.request.method == 'GET'
            send_call = SendCall((response.request,),
                                 TestRedirects.default_keyword_args)
            assert session.calls[-1] == send_call


@pytest.fixture
def list_of_tuples():
    return [
            (('a', 'b'), ('c', 'd')),
            (('c', 'd'), ('a', 'b')),
            (('a', 'b'), ('c', 'd'), ('e', 'f')),
            ]


def test_data_argument_accepts_tuples(list_of_tuples):
    """
    Ensure that the data argument will accept tuples of strings
    and properly encode them.
    """
    for data in list_of_tuples:
        p = PreparedRequest()
        p.prepare(
            method='GET',
            url='http://www.example.com',
            data=data,
            hooks=default_hooks()
        )
        assert p.body == urlencode(data)
        

if __name__ == '__main__':
    unittest.main()
