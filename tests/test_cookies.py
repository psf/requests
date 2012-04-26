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
        self.assertGreaterEqual(len(c), 1)

        # github cookies should not be sent to httpbin.org:
        r2 = requests.get(httpbin('cookies'), cookies=c)
        self.assertEqual(json.loads(r2.text)['cookies'], {})

        # let's do this again using the session object
        s = requests.session()
        s.get("http://github.com")
        self.assertGreaterEqual(len(s.cookies), 1)
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
        self.assertIs(r.cookies, r2.cookies)

    def test_none_cookie(self):
        """Regression test: don't send a Cookie header with a string value of 'None'!"""
        page = json.loads(requests.get(httpbin('headers')).text)
        self.assertNotIn('Cookie', page['headers'])

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
        self.assertGreaterEqual(num_github_cookies, 1)
        # httpbin sets another
        requests.get(httpbin('cookies', 'set', 'key', 'value'), cookies=cookiejar)
        num_total_cookies = len(cookiejar)
        self.assertGreaterEqual(num_total_cookies, 2)
        self.assertGreater(num_total_cookies, num_github_cookies)

        # save and load
        cookiejar.save(ignore_discard=True)
        cookiejar_2 = self.COOKIEJAR_CLASS(self.cookiejar_filename)
        cookiejar_2.load(ignore_discard=True)
        self.assertEqual(len(cookiejar_2), num_total_cookies)
        r = requests.get(httpbin('cookies'), cookies=cookiejar_2)
        self.assertEqual(json.loads(r.text)['cookies'], {'key': 'value'})

class MozCookieJarTest(LWPCookieJarTest):
    """Same test, but substitute MozillaCookieJar."""

    COOKIEJAR_CLASS = cookielib.MozillaCookieJar

if __name__ == '__main__':
    unittest.main()
