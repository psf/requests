#!/usr/bin/env python
# -*- coding: utf-8 -*-



import io
import json
import time
import os
import sys
import unittest

import requests
from requests.compat import str, bytes, StringIO
# import envoy
from requests import HTTPError
from requests.auth import HTTPBasicAuth, HTTPDigestAuth



if (sys.platform == 'win32') and ('HTTPBIN_URL' not in os.environ):
    os.environ['HTTPBIN_URL'] = 'http://httpbin.org/'

# TODO: Detect an open port.
PORT = os.environ.get('HTTPBIN_PORT', '7077')
HTTPBIN_URL = os.environ.get('HTTPBIN_URL', 'http://0.0.0.0:%s/' % (PORT))


def httpbin(*suffix):
    """Returns url for HTTPBIN resource."""

    return HTTPBIN_URL + '/'.join(suffix)


SERVICES = (httpbin, )

_httpbin = False

class RequestsTestSuite(unittest.TestCase):
    """Requests test cases."""

    # It goes to eleven.
    _multiprocess_can_split_ = True

    def setUp(self):

        global _httpbin

        if (not 'HTTPBIN_URL' in os.environ) and not _httpbin:
            # c = envoy.connect('httpbin %s' % (PORT))
            # time.sleep(1)
            _httpbin = True


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

    def test_HTTP_200_OK_GET(self):
        r = requests.get(httpbin('/get'))
        self.assertEqual(r.status_code, 200)

    def test_response_sent(self):
        r = requests.get(httpbin('/get'))

        self.assertTrue(r.request.sent)

    def test_HTTP_302_ALLOW_REDIRECT_GET(self):
        r = requests.get(httpbin('redirect', '1'))
        self.assertEqual(r.status_code, 200)

    def test_HTTP_302_GET(self):
        r = requests.get(httpbin('redirect', '1'), allow_redirects=False)
        self.assertEqual(r.status_code, 302)


    def test_HTTP_200_OK_GET_WITH_PARAMS(self):
        heads = {'User-agent': 'Mozilla/5.0'}

        r = requests.get(httpbin('user-agent'), headers=heads)

        assert heads['User-agent'] in r.text
        self.assertEqual(r.status_code, 200)


    def test_HTTP_200_OK_GET_WITH_MIXED_PARAMS(self):
        heads = {'User-agent': 'Mozilla/5.0'}

        r = requests.get(httpbin('get') + '?test=true', params={'q': 'test'}, headers=heads)
        self.assertEqual(r.status_code, 200)


    def test_user_agent_transfers(self):
        """Issue XX"""

        heads = {
            'User-agent':
                'Mozilla/5.0 (github.com/kennethreitz/requests)'
        }

        r = requests.get(httpbin('user-agent'), headers=heads);
        self.assertTrue(heads['User-agent'] in r.text)

        heads = {
            'user-agent':
                'Mozilla/5.0 (github.com/kennethreitz/requests)'
        }

        r = requests.get(httpbin('user-agent'), headers=heads);
        self.assertTrue(heads['user-agent'] in r.text)


    def test_HTTP_200_OK_HEAD(self):
        r = requests.head(httpbin('/get'))
        self.assertEqual(r.status_code, 200)


    def test_HTTP_200_OK_PUT(self):
        r = requests.put(httpbin('put'))
        self.assertEqual(r.status_code, 200)


    def test_BASICAUTH_TUPLE_HTTP_200_OK_GET(self):

        for service in SERVICES:

            auth = ('user', 'pass')
            url = service('basic-auth', 'user', 'pass')

            r = requests.get(url, auth=auth)
            self.assertEqual(r.status_code, 200)

            r = requests.get(url)
            self.assertEqual(r.status_code, 401)


            s = requests.session(auth=auth)
            r = s.get(url)
            self.assertEqual(r.status_code, 200)


    def test_BASICAUTH_HTTP_200_OK_GET(self):

        for service in SERVICES:

            auth = HTTPBasicAuth('user', 'pass')
            url = service('basic-auth', 'user', 'pass')

            r = requests.get(url, auth=auth)
            self.assertEqual(r.status_code, 200)

            auth = ('user', 'pass')
            r = requests.get(url, auth=auth)
            self.assertEqual(r.status_code, 200)

            r = requests.get(url)
            self.assertEqual(r.status_code, 401)


            s = requests.session(auth=auth)
            r = s.get(url)
            self.assertEqual(r.status_code, 200)


    def test_DIGESTAUTH_HTTP_200_OK_GET(self):

        for service in SERVICES:

            auth = HTTPDigestAuth('user', 'pass')
            url = service('digest-auth', 'auth', 'user', 'pass')

            r = requests.get(url, auth=auth)
            self.assertEqual(r.status_code, 200)

            r = requests.get(url)
            self.assertEqual(r.status_code, 401)


            s = requests.session(auth=auth)
            r = s.get(url)
            self.assertEqual(r.status_code, 200)

    def test_POSTBIN_GET_POST_FILES(self):

        for service in SERVICES:

            url = service('post')
            post = requests.post(url).raise_for_status()

            post = requests.post(url, data={'some': 'data'})
            self.assertEqual(post.status_code, 200)

            post2 = requests.post(url, files={'some': open('test_requests.py')})
            self.assertEqual(post2.status_code, 200)

            post3 = requests.post(url, data='[{"some": "json"}]')
            self.assertEqual(post3.status_code, 200)


    def test_POSTBIN_GET_POST_FILES_WITH_PARAMS(self):

        for service in SERVICES:

            url = service('post')
            post = requests.post(url,
                files={'some': open('test_requests.py')},
                data={'some': 'data'})

            self.assertEqual(post.status_code, 200)


    def test_POSTBIN_GET_POST_FILES_WITH_HEADERS(self):

        for service in SERVICES:

            url = service('post')

            post2 = requests.post(url,
                files={'some': open('test_requests.py')},
                headers = {'User-Agent': 'requests-tests'})

            self.assertEqual(post2.status_code, 200)


    def test_nonzero_evaluation(self):

        for service in SERVICES:

            r = requests.get(service('status', '500'))
            self.assertEqual(bool(r), False)

            r = requests.get(service('/get'))
            self.assertEqual(bool(r), True)


    def test_request_ok_set(self):

        for service in SERVICES:

            r = requests.get(service('status', '404'))
            # print r.status_code
            # r.raise_for_status()
            self.assertEqual(r.ok, False)


    def test_status_raising(self):
        r = requests.get(httpbin('status', '404'))
        self.assertRaises(HTTPError, r.raise_for_status)

        r = requests.get(httpbin('status', '200'))
        self.assertFalse(r.error)
        r.raise_for_status()


    def test_default_status_raising(self):
        config = {'danger_mode': True}
        args = [httpbin('status', '404')]
        kwargs = dict(config=config)
        self.assertRaises(HTTPError, requests.get, *args, **kwargs)

        r = requests.get(httpbin('status', '200'))
        self.assertEqual(r.status_code, 200)


    def test_decompress_gzip(self):

        r = requests.get(httpbin('gzip'))
        r.content.decode('ascii')

    def test_response_has_unicode_url(self):

        for service in SERVICES:

            url = service('get')

            response = requests.get(url)

            assert isinstance(response.url, str)


    def test_unicode_get(self):

        for service in SERVICES:

            url = service('/get')

            requests.get(url, params={'foo': 'føø'})
            requests.get(url, params={'føø': 'føø'})
            requests.get(url, params={'føø': 'føø'})
            requests.get(url, params={'foo': 'foo'})
            requests.get(service('ø'), params={'foo': 'foo'})


    def test_httpauth_recursion(self):

        http_auth = HTTPBasicAuth('user', 'BADpass')

        for service in SERVICES:
            r = requests.get(service('basic-auth', 'user', 'pass'), auth=http_auth)
            self.assertEqual(r.status_code, 401)


    def test_urlencoded_post_data(self):

        for service in SERVICES:

            r = requests.post(service('post'), data=dict(test='fooaowpeuf'))

            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post'))

            rbody = json.loads(r.text)

            self.assertEqual(rbody.get('form'), dict(test='fooaowpeuf'))
            self.assertEqual(rbody.get('data'), '')


    def test_nonurlencoded_post_data(self):

        for service in SERVICES:

            r = requests.post(service('post'), data='fooaowpeuf')

            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post'))

            rbody = json.loads(r.text)
            # Body wasn't valid url encoded data, so the server returns None as
            # "form" and the raw body as "data".

            assert rbody.get('form') in (None, {})
            self.assertEqual(rbody.get('data'), 'fooaowpeuf')


    def test_urlencoded_post_querystring(self):

        for service in SERVICES:

            r = requests.post(service('post'), params=dict(test='fooaowpeuf'))

            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post?test=fooaowpeuf'))

            rbody = json.loads(r.text)
            self.assertEqual(rbody.get('form'), {}) # No form supplied
            self.assertEqual(rbody.get('data'), '')


    def test_urlencoded_post_query_and_data(self):

        for service in SERVICES:

            r = requests.post(
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

            r = requests.post(service('post'), data="foobar")

            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')

            rbody = json.loads(r.text)

            assert rbody.get('form') in (None, {})
            self.assertEqual(rbody.get('data'), 'foobar')


    # def test_idna(self):
    #     r = requests.get(u'http://➡.ws/httpbin')
    #     assert 'httpbin' in r.url


    def test_urlencoded_get_query_multivalued_param(self):

        for service in SERVICES:

            r = requests.get(service('get'), params=dict(test=['foo','baz']))
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.url, service('get?test=foo&test=baz'))


    def test_urlencoded_post_querystring_multivalued(self):

        for service in SERVICES:

            r = requests.post(service('post'), params=dict(test=['foo','baz']))
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post?test=foo&test=baz'))

            rbody = json.loads(r.text)
            self.assertEqual(rbody.get('form'), {}) # No form supplied
            self.assertEqual(rbody.get('data'), '')


    def test_urlencoded_post_query_multivalued_and_data(self):

        for service in SERVICES:

            r = requests.post(
                service('post'),
                params=dict(test=['foo','baz']),
                data=dict(test2="foobar",test3=['foo','baz']))

            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['content-type'], 'application/json')
            self.assertEqual(r.url, service('post?test=foo&test=baz'))

            # print(r.text)
            # print('-----------------------')

            rbody = json.loads(r.text)
            self.assertEqual(rbody.get('form'), dict(test2='foobar',test3=['foo','baz']))
            self.assertEqual(rbody.get('data'), '')


    def test_GET_no_redirect(self):

        for service in SERVICES:

            r = requests.get(service('redirect', '3'), allow_redirects=False)
            self.assertEqual(r.status_code, 302)
            self.assertEqual(len(r.history), 0)


    def test_HEAD_no_redirect(self):

        for service in SERVICES:

            r = requests.head(service('redirect', '3'), allow_redirects=False)
            self.assertEqual(r.status_code, 302)
            self.assertEqual(len(r.history), 0)


    def test_redirect_history(self):

        for service in SERVICES:

            r = requests.get(service('redirect', '3'))
            self.assertEqual(r.status_code, 200)
            self.assertEqual(len(r.history), 3)


    def test_relative_redirect_history(self):

        for service in SERVICES:

            r = requests.get(service('relative-redirect', '3'))
            self.assertEqual(r.status_code, 200)
            self.assertEqual(len(r.history), 3)


    def test_session_HTTP_200_OK_GET(self):

        s = requests.session()
        r = s.get(httpbin('/get'))
        self.assertEqual(r.status_code, 200)


    def test_session_persistent_headers(self):

        heads = {'User-agent': 'Mozilla/5.0'}

        s = requests.session()
        s.headers = heads

        # Make 2 requests from Session object, should send header both times
        r1 = s.get(httpbin('user-agent'))
        assert heads['User-agent'] in r1.text

        r2 = s.get(httpbin('user-agent'))
        assert heads['User-agent'] in r2.text

        new_heads = {'User-agent': 'blah'}
        r3 = s.get(httpbin('user-agent'), headers=new_heads)
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

            response = requests.get(
                url = url,
                hooks = {
                    'args': add_foo_header
                }
            )

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

            response = requests.get(
                url = url,
                hooks = {
                    'args': [add_foo_header, add_bar_header]
                }
            )

            assert 'foo' in response.text
            assert 'bar' in response.text

    def test_session_persistent_cookies(self):

        s = requests.session()

        # Internally dispatched cookies are sent.
        _c = {'kenneth': 'reitz', 'bessie': 'monke'}
        r = s.get(httpbin('cookies'), cookies=_c)
        r = s.get(httpbin('cookies'))

        # Those cookies persist transparently.
        c = json.loads(r.text).get('cookies')
        assert c == _c

        # Double check.
        r = s.get(httpbin('cookies'), cookies={})
        c = json.loads(r.text).get('cookies')
        assert c == _c

        # Remove a cookie by setting it's value to None.
        r = s.get(httpbin('cookies'), cookies={'bessie': None})
        c = json.loads(r.text).get('cookies')
        del _c['bessie']
        assert c == _c

        # Test session-level cookies.
        s = requests.session(cookies=_c)
        r = s.get(httpbin('cookies'))
        c = json.loads(r.text).get('cookies')
        assert c == _c

        # Have the server set a cookie.
        r = s.get(httpbin('cookies', 'set', 'k', 'v'), allow_redirects=True)
        c = json.loads(r.text).get('cookies')

        assert 'k' in c

        # And server-set cookie persistience.
        r = s.get(httpbin('cookies'))
        c = json.loads(r.text).get('cookies')

        assert 'k' in c



    def test_session_persistent_params(self):

        params = {'a': 'a_test'}

        s = requests.session()
        s.params = params

        # Make 2 requests from Session object, should send header both times
        r1 = s.get(httpbin('get'))
        assert params['a'] in r1.text


        params2 = {'b': 'b_test'}

        r2 = s.get(httpbin('get'), params=params2)
        assert params['a'] in r2.text
        assert params2['b'] in r2.text


        params3 = {'b': 'b_test', 'a': None, 'c': 'c_test'}

        r3 = s.get(httpbin('get'), params=params3)

        assert not params['a'] in r3.text
        assert params3['b'] in r3.text
        assert params3['c'] in r3.text

    def test_invalid_content(self):
        # WARNING: if you're using a terrible DNS provider (comcast),
        # this will fail.
        try:
            hah = 'http://somedomainthatclearlydoesntexistg.com'
            r = requests.get(hah, allow_redirects=False)
        except requests.ConnectionError:
            pass   # \o/
        else:
            assert False


        config = {'safe_mode': True}
        r = requests.get(hah, allow_redirects=False, config=config)
        assert r.content == None

    def test_cached_response(self):

        r1 = requests.get(httpbin('get'), prefetch=False)
        assert not r1._content
        assert r1.content
        assert r1.text

        r2 = requests.get(httpbin('get'), prefetch=True)
        assert r2._content
        assert r2.content
        assert r2.text

    def test_iter_lines(self):

        lines = (0, 2, 10, 100)

        for i in lines:
            r = requests.get(httpbin('stream', str(i)), prefetch=False)
            lines = list(r.iter_lines())
            len_lines = len(lines)

            self.assertEqual(i, len_lines)

        # Test 'dangling' fragment in responses that do not terminate in
        # a newline.
        quote = (
            '''Why will he not upon our fair request\n'''
            '''Untent his person and share the air with us?'''
        )

        # Make a request and monkey-patch its contents
        r = requests.get(httpbin('get'))
        r.raw = StringIO(quote)

        # Make sure iter_lines doesn't chop the trailing bit
        lines = '\n'.join(r.iter_lines())
        self.assertEqual(lines, quote)

    def test_safe_mode(self):

        safe = requests.session(config=dict(safe_mode=True))

        # Safe mode creates empty responses for failed requests.
        # Iterating on these responses should produce empty sequences
        r = safe.get('http://_/')
        self.assertEqual(list(r.iter_lines()), [])
        assert isinstance(r.error, requests.exceptions.ConnectionError)

        r = safe.get('http://_/')
        self.assertEqual(list(r.iter_content()), [])
        assert isinstance(r.error, requests.exceptions.ConnectionError)

        # When not in safe mode, should raise Timeout exception
        self.assertRaises(
            requests.exceptions.Timeout,
            requests.get,
            httpbin('stream', '1000'), timeout=0.0001)

        # In safe mode, should return a blank response
        r = requests.get(httpbin('stream', '1000'), timeout=0.0001,
                config=dict(safe_mode=True))
        assert r.content is None
        assert isinstance(r.error, requests.exceptions.Timeout)


if __name__ == '__main__':
    unittest.main()
