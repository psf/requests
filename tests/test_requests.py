#!/usr/bin/env python
# -*- coding: utf-8 -*-

# from __future__ import unicode_literals

# Path hack.
import sys
import os
sys.path.insert(0, os.path.abspath('..'))

import json
import os
import unittest
import pickle
import tempfile

import requests
from requests.compat import str, StringIO
# import envoy
from requests import HTTPError
from requests import get, post, head, put
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

if 'HTTPBIN_URL' not in os.environ:
    os.environ['HTTPBIN_URL'] = 'http://httpbin.org/'

HTTPBIN_URL = os.environ.get('HTTPBIN_URL')


def httpbin(*suffix):
    """Returns url for HTTPBIN resource."""
    return HTTPBIN_URL + '/'.join(suffix)


SERVICES = (httpbin, )

_httpbin = False


class TestSetup(object):
    """Requests test cases."""

    # It goes to eleven.
    _multiprocess_can_split_ = True

    def setUp(self):

        global _httpbin

        if (not 'HTTPBIN_URL' in os.environ) and not _httpbin:
            # c = envoy.connect('httpbin %s' % (PORT))
            # time.sleep(1)
            _httpbin = True


class TestBaseMixin(object):

    def assertCookieHas(self, cookie, **kwargs):
        """Assert that a cookie has various specified properties."""
        for attr, expected_value in kwargs.items():
            cookie_attr = getattr(cookie, attr)
            message = 'Failed comparison for %s: %s != %s' % (attr,
                    cookie_attr, expected_value)
            self.assertEqual(cookie_attr, expected_value, message)


class RequestsTestSuite(TestSetup, TestBaseMixin, unittest.TestCase):
    """Requests test cases."""

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
        self.assertRaises(ValueError, get, 'hiwpefhipowhefopw')

    def test_path_is_not_double_encoded(self):
        request = requests.Request("http://0.0.0.0/get/test case")

        self.assertEqual(request.path_url, "/get/test%20case")

    def test_params_are_added_before_fragment(self):
        request = requests.Request(
            "http://example.com/path#fragment", params={"a": "b"})
        self.assertEqual(request.full_url,
            "http://example.com/path?a=b#fragment")
        request = requests.Request(
            "http://example.com/path?key=value#fragment", params={"a": "b"})
        self.assertEqual(request.full_url,
            "http://example.com/path?key=value&a=b#fragment")

    def test_params_accepts_kv_list(self):
        request = requests.Request('http://example.com/path',
                params=[('a', 'b')])
        self.assertEqual(request.full_url, 'http://example.com/path?a=b')

    def test_HTTP_200_OK_GET(self):
        r = get(httpbin('get'))
        self.assertEqual(r.status_code, 200)

    def test_response_sent(self):
        r = get(httpbin('get'))

        self.assertTrue(r.request.sent)

    def test_HTTP_302_ALLOW_REDIRECT_GET(self):
        r = get(httpbin('redirect', '1'))
        self.assertEqual(r.status_code, 200)

    def test_HTTP_302_GET(self):
        r = get(httpbin('redirect', '1'), allow_redirects=False)
        self.assertEqual(r.status_code, 302)

    def test_HTTP_200_OK_GET_WITH_PARAMS(self):
        heads = {'User-agent': 'Mozilla/5.0'}

        r = get(httpbin('user-agent'), headers=heads)

        assert heads['User-agent'] in r.text
        self.assertEqual(r.status_code, 200)

    def test_HTTP_200_OK_GET_WITH_MIXED_PARAMS(self):
        heads = {'User-agent': 'Mozilla/5.0'}

        r = get(httpbin('get') + '?test=true', params={'q': 'test'},
                headers=heads)
        self.assertEqual(r.status_code, 200)

    # def test_unicode_headers(self):
    #     # Simply calling requests with a unicode instance should simply work
    #     # when the characters are all representable using latin-1:
    #     heads = { u'User-Agent': u'Requests Test Suite' }
    #     requests.get(url=httpbin('get'), headers=heads)

    #     # Characters outside latin-1 should raise an exception:
    #     heads = { u'User-Agent': u'\u30cd\u30c3\u30c8\u30ef\u30fc\u30af' }
    #     self.assertRaises(UnicodeEncodeError, requests.get,
    #                       url=httpbin('get'), headers=heads)

    # def test_session_with_escaped_url(self):
    #     # Test a URL that contains percent-escaped characters
    #     # This URL should not be modified (double-escaped)
    #     # Tests:
    #     # - Quoted illegal characters ("%20" (' '), "%3C" ('<'), "%3E" ('>'))
    #     # - Quoted reserved characters ("%25" ('%'), "%23" ('#'), "%2F" ('/'))
    #     # - Quoted non-ASCII characters ("%C3%98", "%C3%A5")
    #     path_fully_escaped = '%3Ca%25b%23c%2Fd%3E/%C3%98%20%C3%A5'
    #     url = httpbin('get/' + path_fully_escaped)
    #     response = get(url)
    #     self.assertEqual(response.url, httpbin('get/' + path_fully_escaped))

    #     # Test that illegal characters in a path get properly percent-escaped
    #     # Tests:
    #     # - Bare illegal characters (space, '<')
    #     # - Bare non-ASCII characters ('\u00d8')
    #     path = u'<a%25b%23c%2Fd%3E/\u00d8 %C3%A5'
    #     url = httpbin('get/' + path)
    #     response = get(url)
    #     self.assertEqual(response.url, httpbin('get/' + path_fully_escaped))

    #     # Test that reserved characters in a path do not get percent-escaped
    #     # Tests:
    #     # - All reserved characters (RFC 3986), except '?', '#', '[' and ']',
    #     #   which are not allowed in the path, and ';' which delimits
    #     #   parameters.
    #     #   All such characters must be allowed bare in path, and must not be
    #     #   encoded.
    #     # - Special unreserved characters (RFC 3986), which should not be
    #     #   encoded (even though it wouldn't hurt).
    #     path_reserved = '!$&\'()*+,/:=@-._~'
    #     url = httpbin('get/' + path_reserved)
    #     response = get(url)
    #     self.assertEqual(response.url, httpbin('get/' + path_reserved))

    #     # Test that percent-encoded unreserved characters in a path get
    #     # normalised to their un-encoded forms.
    #     path_unreserved = 'ABCDwxyz1234-._~'
    #     path_unreserved_escaped = '%41%42%43%44%77%78%79%7A%31%32%33%34%2D%2E%5F%7E'
    #     url = httpbin('get/' + path_unreserved_escaped)
    #     response = get(url)
    #     self.assertEqual(response.url, httpbin('get/' + path_unreserved))

    #     # Re-run all of the same tests on the query part of the URI
    #     query_fully_escaped = '%3Ca%25b%23c%2Fd%3E=%C3%98%20%C3%A5'
    #     url = httpbin('get/?' + query_fully_escaped)
    #     response = get(url)
    #     self.assertEqual(response.url, httpbin('get/?' + query_fully_escaped))

    #     query = u'<a%25b%23c%2Fd%3E=\u00d8 %C3%A5'
    #     url = httpbin('get/?' + query)
    #     response = get(url)
    #     self.assertEqual(response.url, httpbin('get/?' + query_fully_escaped))

    #     # The legal characters in query happens to be the same as in path
    #     query_reserved = '!$&\'()*+,/:=@-._~'
    #     url = httpbin('get/?' + query_reserved)
    #     response = get(url)
    #     self.assertEqual(response.url, httpbin('get/?' + query_reserved))

    #     query_unreserved = 'ABCDwxyz=1234-._~'
    #     query_unreserved_escaped = '%41%42%43%44%77%78%79%7A=%31%32%33%34%2D%2E%5F%7E'
    #     url = httpbin('get/?' + query_unreserved_escaped)
    #     response = get(url)
    #     self.assertEqual(response.url, httpbin('get/?' + query_unreserved))

    def test_user_agent_transfers(self):
        """Issue XX"""

        heads = {
            'User-agent':
                'Mozilla/5.0 (github.com/kennethreitz/requests)'
        }

        r = get(httpbin('user-agent'), headers=heads)
        self.assertTrue(heads['User-agent'] in r.text)

        heads = {
            'user-agent':
                'Mozilla/5.0 (github.com/kennethreitz/requests)'
        }

        r = get(httpbin('user-agent'), headers=heads)
        self.assertTrue(heads['user-agent'] in r.text)

    def test_HTTP_200_OK_HEAD(self):
        r = head(httpbin('get'))
        self.assertEqual(r.status_code, 200)

    def test_HTTP_200_OK_PUT(self):
        r = put(httpbin('put'))
        self.assertEqual(r.status_code, 200)

    def test_BASICAUTH_TUPLE_HTTP_200_OK_GET(self):

        for service in SERVICES:

            auth = ('user', 'pass')
            url = service('basic-auth', 'user', 'pass')

            r = get(url, auth=auth)
            self.assertEqual(r.status_code, 200)

            r = get(url)
            self.assertEqual(r.status_code, 401)

            s = requests.session(auth=auth)
            r = get(url, session=s)
            self.assertEqual(r.status_code, 200)

    def test_BASICAUTH_HTTP_200_OK_GET(self):

        for service in SERVICES:

            auth = HTTPBasicAuth('user', 'pass')
            url = service('basic-auth', 'user', 'pass')

            r = get(url, auth=auth)
            self.assertEqual(r.status_code, 200)

            auth = ('user', 'pass')
            r = get(url, auth=auth)
            self.assertEqual(r.status_code, 200)

            r = get(url)
            self.assertEqual(r.status_code, 401)

            s = requests.session(auth=auth)
            r = get(url, session=s)
            self.assertEqual(r.status_code, 200)

    def test_DIGESTAUTH_HTTP_200_OK_GET(self):

        for service in SERVICES:

            auth = HTTPDigestAuth('user', 'pass')
            url = service('digest-auth', 'auth', 'user', 'pass')

            r = get(url, auth=auth)
            self.assertEqual(r.status_code, 200)

            r = get(url)
            self.assertEqual(r.status_code, 401)

            s = requests.session(auth=auth)
            r = get(url, session=s)
            self.assertEqual(r.status_code, 200)

    def test_DIGESTAUTH_WRONG_HTTP_401_GET(self):

        for service in SERVICES:

            auth = HTTPDigestAuth('user', 'wrongpass')
            url = service('digest-auth', 'auth', 'user', 'pass')

            r = get(url, auth=auth)
            self.assertEqual(r.status_code, 401)

            s = requests.session(auth=auth)
            r = get(url, session=s)
            self.assertEqual(r.status_code, 401)

    def test_POSTBIN_GET_POST_FILES(self):

        for service in SERVICES:

            url = service('post')
            post1 = post(url).raise_for_status()

            post1 = post(url, data={'some': 'data'})
            self.assertEqual(post1.status_code, 200)

            with open(__file__) as f:
                post2 = post(url, files={'some': f})
                post3 = post(url, files=[('some', f)])
            self.assertEqual(post2.status_code, 200)
            self.assertEqual(post3.status_code, 200)

            post4 = post(url, data='[{"some": "json"}]')
            self.assertEqual(post4.status_code, 200)

            try:
                post(url, files=['bad file data'])
            except ValueError:
                pass

    def test_POSTBIN_GET_POST_FILES_WITH_PARAMS(self):

        for service in SERVICES:

            with open(__file__) as f:
                url = service('post')
                post1 = post(url,
                             files={'some': f},
                             data={'some': 'data'})
                post2 = post(url, data={'some': 'data'}, files=[('some', f)])
                post3 = post(url, data=[('some', 'data')],
                        files=[('some', f)])

            self.assertEqual(post1.status_code, 200)
            self.assertEqual(post2.status_code, 200)
            self.assertEqual(post3.status_code, 200)

    def test_POSTBIN_GET_POST_FILES_WITH_HEADERS(self):

        for service in SERVICES:

            url = service('post')

            with open(__file__) as f:

                post2 = post(url,
                    files={'some': f},
                    headers={'User-Agent': 'requests-tests'})

            self.assertEqual(post2.status_code, 200)

    def test_POSTBIN_GET_POST_FILES_STRINGS(self):

        for service in SERVICES:

            url = service('post')

            post1 = post(url, files={'fname.txt': 'fdata'})
            self.assertEqual(post1.status_code, 200)

            post2 = post(url, files={'fname.txt': 'fdata',
                    'fname2.txt': 'more fdata'})
            self.assertEqual(post2.status_code, 200)

            post3 = post(url, files={'fname.txt': 'fdata',
                    'fname2.txt': open(__file__, 'rb')})
            self.assertEqual(post3.status_code, 200)

            post4 = post(url, files={'fname.txt': 'fdata'})
            self.assertEqual(post4.status_code, 200)

            post5 = post(url, files={'file': ('file.txt', 'more fdata')})
            self.assertEqual(post5.status_code, 200)

            # Dirty hack to tide us over until 3.3.
            # TODO: Remove this hack when Python 3.3 is released.
            if (sys.version_info[0] == 2):
                fdata = '\xc3\xa9'.decode('utf-8')
            else:
                fdata = '\xe9'

            post6 = post(url, files={'fname.txt': fdata})
            self.assertEqual(post6.status_code, 200)

            post7 = post(url, files={'fname.txt': 'fdata to verify'})
            rbody = json.loads(post7.text)
            self.assertTrue(rbody.get('files', None))
            self.assertTrue(rbody['files'].get('fname.txt', None))
            self.assertEqual(rbody['files']['fname.txt'], 'fdata to verify')

            post8 = post(url, files=[('fname.txt', 'fdata')])
            self.assertEqual(post8.status_code, 200)
            resp_body = post8.json
            self.assertTrue(resp_body.get('files', None))
            self.assertTrue(resp_body['files'].get('fname.txt', None))
            self.assertEqual(resp_body['files']['fname.txt'], 'fdata')

            post9 = post(url, files=[('fname.txt', fdata)])
            self.assertEqual(post9.status_code, 200)

            post10 = post(url, files=[('file',
                        ('file.txt', 'more file data'))])
            self.assertEqual(post10.status_code, 200)

            post11 = post(url, files=[('fname.txt', 'fdata'),
                    ('fname2.txt', 'more fdata')])
            post12 = post(url, files=[('fname.txt', 'fdata'),
                    ('fname2.txt', open(__file__, 'rb'))])
            self.assertEqual(post11.status_code, 200)
            self.assertEqual(post12.status_code, 200)

    def test_nonzero_evaluation(self):

        for service in SERVICES:

            r = get(service('status', '500'))
            self.assertEqual(bool(r), False)

            r = get(service('/get'))
            self.assertEqual(bool(r), True)

    def test_request_ok_set(self):

        for service in SERVICES:

            r = get(service('status', '404'))
            # print r.status_code
            # r.raise_for_status()
            self.assertEqual(r.ok, False)

    def test_status_raising(self):
        r = get(httpbin('status', '404'))
        self.assertRaises(HTTPError, r.raise_for_status)

        r = get(httpbin('status', '200'))
        self.assertFalse(r.error)
        r.raise_for_status()

    def test_default_status_raising(self):
        config = {'danger_mode': True}
        args = [httpbin('status', '404')]
        kwargs = dict(config=config)
        self.assertRaises(HTTPError, get, *args, **kwargs)

        r = get(httpbin('status', '200'))
        self.assertEqual(r.status_code, 200)

    def test_decompress_gzip(self):

        r = get(httpbin('gzip'))
        r.content.decode('ascii')

    def test_response_has_unicode_url(self):

        for service in SERVICES:

            url = service('get')

            response = get(url)

            assert isinstance(response.url, str)

    def test_unicode_get(self):

        for service in SERVICES:

            url = service('/get')

            get(url, params={'foo': 'føø'})
            get(url, params={'føø': 'føø'})
            get(url, params={'føø': 'føø'})
            get(url, params={'foo': 'foo'})
            get(service('ø'), params={'foo': 'foo'})

    def test_httpauth_recursion(self):

        http_auth = HTTPBasicAuth('user', 'BADpass')

        for service in SERVICES:
            r = get(service('basic-auth', 'user', 'pass'), auth=http_auth)
            self.assertEqual(r.status_code, 401)

    def test_urlencoded_post_data(self):

        for service in SERVICES:

            r = post(service('post'), data=dict(test='fooaowpeuf'))

            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post'))

            rbody = json.loads(r.text)

            self.assertEqual(rbody.get('form'), dict(test='fooaowpeuf'))
            self.assertEqual(rbody.get('data'), '')

    def test_nonurlencoded_post_data(self):

        for service in SERVICES:

            r = post(service('post'), data='fooaowpeuf')

            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post'))

            rbody = json.loads(r.text)
            # Body wasn't valid url encoded data, so the server returns None as
            # "form" and the raw body as "data".

            assert rbody.get('form') in (None, {})
            self.assertEqual(rbody.get('data'), 'fooaowpeuf')

    def test_file_post_data(self):

        filecontent = b"fooaowpeufbarasjhf"
        testfile = tempfile.NamedTemporaryFile(delete=False)
        testfile.write(filecontent)
        testfile.flush()
        testfile.close()

        for service in SERVICES:

            data = open(testfile.name, "rb")
            r = post(service('post'), data=data,
                    headers={"content-type": "application/octet-stream"})

            data.close()
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post'))

            rbody = json.loads(r.text)
            assert rbody.get('form') in (None, {})
            self.assertEqual(rbody.get('data'), filecontent.decode('ascii'))
        os.remove(testfile.name)

    def test_urlencoded_post_querystring(self):

        for service in SERVICES:

            r = post(service('post'), params=dict(test='fooaowpeuf'))

            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post?test=fooaowpeuf'))

            rbody = json.loads(r.text)
            self.assertEqual(rbody.get('form'), {})  # No form supplied
            self.assertEqual(rbody.get('data'), '')

    def test_urlencoded_post_query_and_data(self):

        for service in SERVICES:

            r = post(
                service('post'),
                params=dict(test='fooaowpeuf'),
                data=dict(test2="foobar"))

            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post?test=fooaowpeuf'))

            rbody = json.loads(r.text)
            self.assertEqual(rbody.get('form'), dict(test2='foobar'))
            self.assertEqual(rbody.get('data'), '')

    def test_nonurlencoded_postdata(self):

        for service in SERVICES:

            r = post(service('post'), data="foobar")

            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')

            rbody = json.loads(r.text)

            assert rbody.get('form') in (None, {})
            self.assertEqual(rbody.get('data'), 'foobar')

    def test_urlencoded_get_query_multivalued_param(self):

        for service in SERVICES:

            r = get(service('get'), params=dict(test=['foo', 'baz']))
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.url, service('get?test=foo&test=baz'))

    def test_urlencoded_post_querystring_multivalued(self):

        for service in SERVICES:

            r = post(service('post'), params=dict(test=['foo', 'baz']))
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post?test=foo&test=baz'))

            rbody = json.loads(r.text)
            self.assertEqual(rbody.get('form'), {})  # No form supplied
            self.assertEqual(rbody.get('data'), '')

    def test_urlencoded_post_query_multivalued_and_data(self):

        for service in SERVICES:

            r = post(
                service('post'),
                params=dict(test=['foo', 'baz']),
                data=dict(test2="foobar", test3=['foo', 'baz']))

            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post?test=foo&test=baz'))

            # print(r.text)
            # print('-----------------------')

            rbody = json.loads(r.text)
            self.assertEqual(rbody.get('form'), dict(test2='foobar', test3=['foo', 'baz']))
            self.assertEqual(rbody.get('data'), '')

    def test_GET_no_redirect(self):

        for service in SERVICES:

            r = get(service('redirect', '3'), allow_redirects=False)
            self.assertEqual(r.status_code, 302)
            self.assertEqual(len(r.history), 0)

    def test_HEAD_no_redirect(self):

        for service in SERVICES:

            r = head(service('redirect', '3'), allow_redirects=False)
            self.assertEqual(r.status_code, 302)
            self.assertEqual(len(r.history), 0)

    def test_redirect_history(self):

        for service in SERVICES:

            r = get(service('redirect', '3'))
            self.assertEqual(r.status_code, 200)
            self.assertEqual(len(r.history), 3)

    def test_relative_redirect_history(self):

        for service in SERVICES:

            r = get(service('relative-redirect', '3'))
            self.assertEqual(r.status_code, 200)
            self.assertEqual(len(r.history), 3)

    def test_session_HTTP_200_OK_GET(self):

        s = requests.session()
        r = get(httpbin('get'), session=s)
        self.assertEqual(r.status_code, 200)

    def test_session_persistent_headers(self):

        heads = {'User-agent': 'Mozilla/5.0'}

        s = requests.session()
        s.headers = heads

        # Make 2 requests from Session object, should send header both times
        r1 = get(httpbin('user-agent'), session=s)
        assert heads['User-agent'] in r1.text

        r2 = get(httpbin('user-agent'), session=s)
        assert heads['User-agent'] in r2.text

        new_heads = {'User-agent': 'blah'}
        r3 = get(httpbin('user-agent'), headers=new_heads, session=s)
        assert new_heads['User-agent'] in r3.text

        self.assertEqual(r2.status_code, 200)

    def test_single_hook(self):

        def add_foo_header(args):
            if not args.get('headers'):
                args['headers'] = {}

            args['headers'].update({
                'X-Foo': 'foo'
            })

            return args

        for service in SERVICES:
            url = service('headers')
            response = get(url=url, hooks={'args': add_foo_header})

            assert 'foo' in response.text

    def test_multiple_hooks(self):

        def add_foo_header(args):
            if not args.get('headers'):
                args['headers'] = {}

            args['headers'].update({
                'X-Foo': 'foo'
            })

            return args

        def add_bar_header(args):
            if not args.get('headers'):
                args['headers'] = {}

            args['headers'].update({
                'X-Bar': 'bar'
            })

            return args

        for service in SERVICES:
            url = service('headers')

            response = get(url=url,
                hooks={
                    'args': [add_foo_header, add_bar_header]
                }
            )

            assert 'foo' in response.text
            assert 'bar' in response.text

    def test_session_persistent_cookies(self):

        s = requests.session()

        # Internally dispatched cookies are sent.
        _c = {'kenneth': 'reitz', 'bessie': 'monke'}
        r = get(httpbin('cookies'), cookies=_c, session=s)
        r = get(httpbin('cookies'), session=s)

        # Those cookies persist transparently.
        c = json.loads(r.text).get('cookies')
        self.assertEqual(c, _c)

        # Double check.
        r = get(httpbin('cookies'), cookies={}, session=s)
        c = json.loads(r.text).get('cookies')
        self.assertEqual(c, _c)

        # Remove a cookie by setting it's value to None.
        r = get(httpbin('cookies'), cookies={'bessie': None}, session=s)
        c = json.loads(r.text).get('cookies')
        del _c['bessie']
        self.assertEqual(c, _c)

        # Test session-level cookies.
        s = requests.session(cookies=_c)
        r = get(httpbin('cookies'), session=s)
        c = json.loads(r.text).get('cookies')
        self.assertEqual(c, _c)

        # Have the server set a cookie.
        r = get(httpbin('cookies', 'set', 'k', 'v'), allow_redirects=True,
                session=s)
        c = json.loads(r.text).get('cookies')

        assert 'k' in c

        # And server-set cookie persistience.
        r = get(httpbin('cookies'), session=s)
        c = json.loads(r.text).get('cookies')

        assert 'k' in c

    def test_session_persistent_params(self):

        params = {'a': 'a_test'}

        s = requests.session()
        s.params = params

        # Make 2 requests from Session object, should send header both times
        r1 = get(httpbin('get'), session=s)
        assert params['a'] in r1.text

        params2 = {'b': 'b_test'}

        r2 = get(httpbin('get'), params=params2, session=s)
        assert params['a'] in r2.text
        assert params2['b'] in r2.text

        params3 = {'b': 'b_test', 'a': None, 'c': 'c_test'}

        r3 = get(httpbin('get'), params=params3, session=s)

        assert not params['a'] in r3.text
        assert params3['b'] in r3.text
        assert params3['c'] in r3.text

    def test_session_cookies_with_return_response_false(self):
        s = requests.session()
        # return_response=False as it does requests.async.get
        rq = get(httpbin('cookies', 'set', 'k', 'v'), return_response=False,
                 allow_redirects=True, session=s)
        rq.send(prefetch=True)
        c = rq.response.json.get('cookies')
        assert 'k' in c
        assert 'k' in s.cookies

    def test_session_pickling(self):

        s = requests.session(
                headers={'header': 'value'},
                cookies={'a-cookie': 'cookie-value'},
                auth=('username', 'password'))

        ds = pickle.loads(pickle.dumps(s))

        self.assertEqual(s.headers, ds.headers)
        self.assertEqual(s.auth, ds.auth)

        # Cookie doesn't have a good __eq__, so verify manually:
        self.assertEqual(len(ds.cookies), 1)
        for cookie in ds.cookies:
            self.assertCookieHas(cookie, name='a-cookie', value='cookie-value')

    def test_unpickled_session_requests(self):
        s = requests.session()
        r = get(httpbin('cookies', 'set', 'k', 'v'), allow_redirects=True,
                session=s)
        c = json.loads(r.text).get('cookies')
        assert 'k' in c

        ds = pickle.loads(pickle.dumps(s))
        r = get(httpbin('cookies'), session=ds)
        c = json.loads(r.text).get('cookies')
        assert 'k' in c

        ds1 = pickle.loads(pickle.dumps(requests.session()))
        ds2 = pickle.loads(pickle.dumps(requests.session(prefetch=False)))
        assert ds1.prefetch
        assert not ds2.prefetch

    # def test_invalid_content(self):
    #     # WARNING: if you're using a terrible DNS provider (comcast),
    #     # this will fail.
    #     try:
    #         hah = 'http://somedomainthatclearlydoesntexistg.com'
    #         r = get(hah, allow_redirects=False)
    #     except requests.ConnectionError:
    #         pass   # \o/
    #     else:
    #         assert False

    #     config = {'safe_mode': True}
    #     r = get(hah, allow_redirects=False, config=config)
    #     assert r.content == None

    def test_cached_response(self):

        r1 = get(httpbin('get'), prefetch=False)
        assert not r1._content
        assert r1.content
        assert r1.text

        r2 = get(httpbin('get'), prefetch=True)
        assert r2._content
        assert r2.content
        assert r2.text

    def test_iter_lines(self):

        lines = (0, 2, 10, 100)

        for i in lines:
            r = get(httpbin('stream', str(i)), prefetch=False)
            lines = list(r.iter_lines())
            len_lines = len(lines)

            self.assertEqual(i, len_lines)

        # Tests that trailing whitespaces within lines do not get stripped.
        # Tests that a trailing non-terminated line does not get stripped.
        quote = (
            '''Agamemnon  \n'''
            '''\tWhy will he not upon our fair request\r\n'''
            '''\tUntent his person and share the air with us?'''
        )

        # Make a request and monkey-patch its contents
        r = get(httpbin('get'), prefetch=False)
        r.raw = StringIO(quote)

        lines = list(r.iter_lines())
        len_lines = len(lines)
        self.assertEqual(len_lines, 3)

        joined = lines[0] + '\n' + lines[1] + '\r\n' + lines[2]
        self.assertEqual(joined, quote)

    # def test_safe_mode(self):

    #     safe = requests.session(config=dict(safe_mode=True))

    #     # Safe mode creates empty responses for failed requests.
    #     # Iterating on these responses should produce empty sequences
    #     r = get('http://0.0.0.0:700/', session=safe)
    #     self.assertEqual(list(r.iter_lines()), [])
    #     assert isinstance(r.error, requests.exceptions.ConnectionError)

    #     r = get('http://0.0.0.0:789/', session=safe)
    #     self.assertEqual(list(r.iter_content()), [])
    #     assert isinstance(r.error, requests.exceptions.ConnectionError)

    #     # When not in safe mode, should raise Timeout exception
    #     self.assertRaises(
    #         requests.exceptions.Timeout,
    #         get,
    #         httpbin('stream', '1000'), timeout=0.0001)

    #     # In safe mode, should return a blank response
    #     r = get(httpbin('stream', '1000'), timeout=0.0001,
    #             config=dict(safe_mode=True))
    #     assert r.content is None
    #     assert isinstance(r.error, requests.exceptions.Timeout)

    def test_upload_binary_data(self):

        requests.get(httpbin('post'), auth=('a', 'b'), data='\xff')

    def test_useful_exception_for_invalid_port(self):
        # If we pass a legitimate URL with an invalid port, we should fail.
        self.assertRaises(
              ValueError,
              get,
              'http://google.com:banana')

    def test_useful_exception_for_invalid_scheme(self):

        # If we pass a legitimate URL with a scheme not supported
        # by requests, we should fail.
        self.assertRaises(
              ValueError,
              get,
              'ftp://ftp.kernel.org/pub/')

    def test_can_have_none_in_header_values(self):
        try:
            # Don't choke on headers with none in the value.
            requests.get(httpbin('headers'), headers={'Foo': None})
        except TypeError:
            self.fail()

    def test_danger_mode_redirects(self):
        s = requests.session()
        s.config['danger_mode'] = True
        s.get(httpbin('redirect', '4'))

    def test_empty_response(self):
        r = requests.get(httpbin('status', '404'))
        r.text

    def test_max_redirects(self):
        """Test the max_redirects config variable, normally and under
        safe_mode.
        """
        def unsafe_callable():
            requests.get(httpbin('redirect', '3'),
                    config=dict(max_redirects=2))
        self.assertRaises(requests.exceptions.TooManyRedirects,
                unsafe_callable)

        # add safe mode
        response = requests.get(httpbin('redirect', '3'),
                config=dict(safe_mode=True, max_redirects=2))
        self.assertTrue(response.content is None)
        self.assertTrue(isinstance(response.error,
                requests.exceptions.TooManyRedirects))

    def test_connection_keepalive_and_close(self):
        """Test that we send 'Connection: close' when keep_alive is
        disabled.
        """
        # keep-alive should be on by default
        r1 = requests.get(httpbin('get'))
        # XXX due to proxying issues, test the header sent back by httpbin, rather than
        # the header reported in its message body. See kennethreitz/httpbin#46
        self.assertEqual(r1.headers['Connection'].lower(), 'keep-alive')

        # but when we disable it, we should send a 'Connection: close'
        # and get the same back:
        r2 = requests.get(httpbin('get'), config=dict(keep_alive=False))
        self.assertEqual(r2.headers['Connection'].lower(), 'close')

    def test_head_content(self):
        """Test that empty bodies are properly supported."""

        r = requests.head(httpbin('headers'))
        r.content
        r.text

    def test_post_fields_with_multiple_values_and_files(self):
        """Test that it is possible to POST using the files argument and a
        list for a value in the data argument."""

        data = {'field': ['a', 'b']}
        files = {'file': 'Garbled data'}
        r = post(httpbin('post'), data=data, files=files)
        t = json.loads(r.text)
        self.assertEqual(t.get('form'), {'field': 'a, b'})
        self.assertEqual(t.get('files'), files)
        r = post(httpbin('post'), data=data, files=files.items())
        t = r.json
        self.assertEqual(t.get('form'), {'field': 'a, b'})
        self.assertEqual(t.get('files'), files)

    def test_str_data_content_type(self):
        data = 'test string data'
        r = post(httpbin('post'), data=data)
        t = json.loads(r.text)
        self.assertEqual(t.get('headers').get('Content-Type'), '')


if __name__ == '__main__':
    unittest.main()
