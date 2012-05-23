#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
import os
import tempfile
import unittest

# Path hack.
sys.path.insert(0, os.path.abspath('..'))
import requests
from requests.compat import cookielib

# More hacks
sys.path.append('.')
from test_requests import httpbin, TestBaseMixin

class CookieTests(TestBaseMixin, unittest.TestCase):

    def test_cookies_from_response(self):
        """Basic test that we correctly parse received cookies in the Response object."""
        r = requests.get(httpbin('cookies', 'set', 'myname', 'myvalue'))

        # test deprecated dictionary interface
        self.assertEqual(r.cookies['myname'], 'myvalue')
        self.assertEqual(r.cookies.get('myname'), 'myvalue')
        # test CookieJar interface
        jar = r.cookies
        self.assertEqual(len(jar), 1)
        cookie_from_jar = list(jar)[0]
        self.assertCookieHas(cookie_from_jar, name='myname', value='myvalue')

        q = requests.get(httpbin('cookies'), cookies=jar)
        self.assertEqual(json.loads(q.text)['cookies'], {'myname': 'myvalue'})

    def test_crossdomain_cookies(self):
        """Cookies should not be sent to domains they didn't originate from."""
        r = requests.get("http://github.com")
        c = r.cookies
        # github should send us cookies
        self.assertTrue(len(c) >= 1)

        # github cookies should not be sent to httpbin.org:
        r2 = requests.get(httpbin('cookies'), cookies=c)
        self.assertEqual(json.loads(r2.text)['cookies'], {})

        # let's do this again using the session object
        s = requests.session()
        s.get("http://github.com")
        self.assertTrue(len(s.cookies) >= 1)
        r = s.get(httpbin('cookies'))
        self.assertEqual(json.loads(r.text)['cookies'], {})
        # we can set a cookie and get exactly that same-domain cookie back:
        r = s.get(httpbin('cookies', 'set', 'myname', 'myvalue'))
        self.assertEqual(json.loads(r.text)['cookies'], {'myname': 'myvalue'})

    def test_overwrite(self):
        """Cookies should get overwritten when appropriate."""
        r = requests.get(httpbin('cookies', 'set', 'shimon', 'yochai'))
        cookies = r.cookies
        requests.get(httpbin('cookies', 'set', 'elazar', 'shimon'), cookies=cookies)
        r = requests.get(httpbin('cookies'), cookies=cookies)
        self.assertEqual(json.loads(r.text)['cookies'],
                {'shimon': 'yochai', 'elazar': 'shimon'})
        # overwrite the value of 'shimon'
        r = requests.get(httpbin('cookies', 'set', 'shimon', 'gamaliel'), cookies=cookies)
        self.assertEqual(len(cookies), 2)
        r = requests.get(httpbin('cookies'), cookies=cookies)
        self.assertEqual(json.loads(r.text)['cookies'],
                {'shimon': 'gamaliel', 'elazar': 'shimon'})

    def test_redirects(self):
        """Test that cookies set by a 302 page are correctly processed."""
        r = requests.get(httpbin('cookies', 'set', 'redirects', 'work'))
        self.assertEqual(r.history[0].status_code, 302)
        expected_cookies = {'redirects': 'work'}
        self.assertEqual(json.loads(r.text)['cookies'], expected_cookies)

        r2 = requests.get(httpbin('cookies', 'set', 'very', 'well'), cookies=r.cookies)
        expected_cookies = {'redirects': 'work', 'very': 'well'}
        self.assertEqual(json.loads(r2.text)['cookies'], expected_cookies)
        self.assertTrue(r.cookies is r2.cookies)

    def test_none_cookie(self):
        """Regression test: don't send a Cookie header with a string value of 'None'!"""
        page = json.loads(requests.get(httpbin('headers')).text)
        self.assertTrue('Cookie' not in page['headers'])

    def test_secure_cookies(self):
        """Test that secure cookies can only be sent via https."""
        header = "Set-Cookie: ThisIsA=SecureCookie; Path=/; Secure; HttpOnly"
        url = 'https://httpbin.org/response-headers?%s' % (requests.utils.quote(header),)
        cookies = requests.get(url, verify=False).cookies
        self.assertEqual(len(cookies), 1)
        self.assertEqual(list(cookies)[0].secure, True)

        secure_resp = requests.get('https://httpbin.org/cookies', cookies=cookies, verify=False)
        secure_cookies_sent = json.loads(secure_resp.text)['cookies']
        self.assertEqual(secure_cookies_sent, {'ThisIsA': 'SecureCookie'})

        insecure_resp = requests.get('http://httpbin.org/cookies', cookies=cookies)
        insecure_cookies_sent = json.loads(insecure_resp.text)['cookies']
        self.assertEqual(insecure_cookies_sent, {})

    def test_disabled_cookie_persistence(self):
        """Test that cookies are not persisted when configured accordingly."""

        config = {'store_cookies' : False}

        # Check the case when no cookie is passed as part of the request and the one in response is ignored
        cookies = requests.get(httpbin('cookies', 'set', 'key', 'value'), config = config).cookies
        self.assertTrue(cookies.get("key") is None)

        # Test that the cookies passed while making the request still gets used and is available in response object.
        # only the ones received from server is not saved
        cookies_2 = requests.get(httpbin('cookies', 'set', 'key', 'value'), config = config,\
                                                cookies = {"key_2" : "value_2"}).cookies
        self.assertEqual(len(cookies_2), 1)
        self.assertEqual(cookies_2.get("key_2"), "value_2")

        # Use the session and make sure that the received cookie is not used in subsequent calls
        s = requests.session()
        s.get(httpbin('cookies', 'set', 'key', 'value'), config = config)
        r = s.get(httpbin('cookies'))
        self.assertEqual(json.loads(r.text)['cookies'], {})

    def test_jar_utility_functions(self):
        """Test utility functions such as list_domains, list_paths, multiple_domains."""
        r = requests.get("http://github.com")
        c = r.cookies
        # github should send us cookies
        self.assertTrue(len(c) >= 1)
        self.assertEqual(len(c), len(r.cookies.keys()))
        self.assertEqual(len(c), len(r.cookies.values()))
        self.assertEqual(len(c), len(r.cookies.items()))
        
        # domain and path utility functions
        domain = r.cookies.list_domains()[0]
        path = r.cookies.list_paths()[0]
        self.assertEqual(dict(r.cookies), r.cookies.get_dict(domain=domain, path=path))
        self.assertEqual(len(r.cookies.list_domains()), 1)
        self.assertEqual(len(r.cookies.list_paths()), 1)
        self.assertFalse(r.cookies.multiple_domains())

    def test_convert_jar_to_dict(self):
        """Test that keys, values, and items are defined and that we can convert
        cookie jars to plain old Python dicts."""
        r = requests.get(httpbin('cookies', 'set', 'myname', 'myvalue'))

        # test keys, values, and items
        self.assertEqual(r.cookies.keys(), ['myname'])
        self.assertEqual(r.cookies.values(), ['myvalue'])
        self.assertEqual(r.cookies.items(), [('myname','myvalue')])
        
        # test if we can convert jar to dict
        dictOfCookies = dict(r.cookies)
        self.assertEqual(dictOfCookies, {'myname':'myvalue'})
        self.assertEqual(dictOfCookies, r.cookies.get_dict())

class LWPCookieJarTest(TestBaseMixin, unittest.TestCase):
    """Check store/load of cookies to FileCookieJar's, specifically LWPCookieJar's."""

    COOKIEJAR_CLASS = cookielib.LWPCookieJar

    def setUp(self):
        # blank the file
        self.cookiejar_file = tempfile.NamedTemporaryFile()
        self.cookiejar_filename = self.cookiejar_file.name
        cookiejar = self.COOKIEJAR_CLASS(self.cookiejar_filename)
        cookiejar.save()

    def tearDown(self):
        try:
            self.cookiejar_file.close()
        except OSError:
            pass

    def test_cookiejar_persistence(self):
        """Test that we can save cookies to a FileCookieJar."""
        cookiejar = self.COOKIEJAR_CLASS(self.cookiejar_filename)
        cookiejar.load()
        # initially should be blank
        self.assertEqual(len(cookiejar), 0)

        response = requests.get(httpbin('cookies', 'set', 'key', 'value'), cookies=cookiejar)
        self.assertEqual(len(cookiejar), 1)
        cookie = list(cookiejar)[0]
        self.assertEqual(json.loads(response.text)['cookies'], {'key': 'value'})
        self.assertCookieHas(cookie, name='key', value='value')

        # save and reload the cookies from the file:
        cookiejar.save(ignore_discard=True)
        cookiejar_2 = self.COOKIEJAR_CLASS(self.cookiejar_filename)
        cookiejar_2.load(ignore_discard=True)
        self.assertEqual(len(cookiejar_2), 1)
        cookie_2 = list(cookiejar_2)[0]
        # this cookie should have been saved with the correct domain restriction:
        self.assertCookieHas(cookie_2, name='key', value='value',
                domain='httpbin.org', path='/')

        # httpbin sets session cookies, so if we don't ignore the discard attribute,
        # there should be no cookie:
        cookiejar_3 = self.COOKIEJAR_CLASS(self.cookiejar_filename)
        cookiejar_3.load()
        self.assertEqual(len(cookiejar_3), 0)

    def test_crossdomain(self):
        """Test persistence of the domains associated with the cookies."""
        cookiejar = self.COOKIEJAR_CLASS(self.cookiejar_filename)
        cookiejar.load()
        self.assertEqual(len(cookiejar), 0)

        # github sets a cookie
        requests.get("http://github.com", cookies=cookiejar)
        num_github_cookies = len(cookiejar)
        self.assertTrue(num_github_cookies >= 1)
        # httpbin sets another
        requests.get(httpbin('cookies', 'set', 'key', 'value'), cookies=cookiejar)
        num_total_cookies = len(cookiejar)
        self.assertTrue(num_total_cookies >= 2)
        self.assertTrue(num_total_cookies > num_github_cookies)

        # save and load
        cookiejar.save(ignore_discard=True)
        cookiejar_2 = self.COOKIEJAR_CLASS(self.cookiejar_filename)
        cookiejar_2.load(ignore_discard=True)
        self.assertEqual(len(cookiejar_2), num_total_cookies)
        r = requests.get(httpbin('cookies'), cookies=cookiejar_2)
        self.assertEqual(json.loads(r.text)['cookies'], {'key': 'value'})

    def test_persistent_cookies(self):
        """Test that we correctly interpret persistent cookies."""
        # httpbin's normal cookie methods don't send persistent cookies,
        # so cook up the appropriate header and force it to send
        header = "Set-Cookie: Persistent=CookiesAreScary; expires=Sun, 04-May-2032 04:56:50 GMT; path=/"
        url = httpbin('response-headers?%s' % (requests.utils.quote(header),))
        cookiejar = self.COOKIEJAR_CLASS(self.cookiejar_filename)

        requests.get(url, cookies=cookiejar)
        self.assertEqual(len(cookiejar), 1)
        self.assertCookieHas(list(cookiejar)[0], name='Persistent', value='CookiesAreScary')

        requests.get(httpbin('cookies', 'set', 'ThisCookieIs', 'SessionOnly'), cookies=cookiejar)
        self.assertEqual(len(cookiejar), 2)
        self.assertEqual(len([c for c in cookiejar if c.name == 'Persistent']), 1)
        self.assertEqual(len([c for c in cookiejar if c.name == 'ThisCookieIs']), 1)

        # save and load
        cookiejar.save()
        cookiejar_2 = self.COOKIEJAR_CLASS(self.cookiejar_filename)
        cookiejar_2.load()
        # we should only load the persistent cookie
        self.assertEqual(len(cookiejar_2), 1)
        self.assertCookieHas(list(cookiejar_2)[0], name='Persistent', value='CookiesAreScary')

class MozCookieJarTest(LWPCookieJarTest):
    """Same test, but substitute MozillaCookieJar."""

    COOKIEJAR_CLASS = cookielib.MozillaCookieJar

if __name__ == '__main__':
    unittest.main()
