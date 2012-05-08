#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Path hack.
import sys, os
sys.path.insert(0, os.path.abspath('..'))

import sys
import unittest

import select
has_poll = hasattr(select, "poll")

from requests import async
import requests

sys.path.append('.')
from test_requests import httpbin, RequestsTestSuite, SERVICES


class RequestsTestSuiteUsingAsyncApi(RequestsTestSuite):
    """Requests async test cases."""

    def patched(f):
        """Automatically send request after creation."""

        def wrapped(*args, **kwargs):

            request = f(*args, **kwargs)
            return async.map([request])[0]

        return wrapped

    # Patched requests.api functions.
    global request
    request = patched(async.request)

    global delete, get, head, options, patch, post, put
    delete = patched(async.delete)
    get = patched(async.get)
    head = patched(async.head)
    options = patched(async.options)
    patch = patched(async.patch)
    post = patched(async.post)
    put = patched(async.put)


    def test_entry_points(self):

        async.request

        async.delete
        async.get
        async.head
        async.options
        async.patch
        async.post
        async.put

        async.map
        async.send

    def test_select_poll(self):
        """Test to make sure we don't overwrite the poll"""
        self.assertEqual(hasattr(select, "poll"), has_poll)

    def test_async_with_session_cookies(self):
        s = requests.Session(cookies={'initial': '42'})
        r1 = get(httpbin('cookies/set/async/yes'), session=s)
        r2 = get(httpbin('cookies/set/no_session/yes'))
        assert 'initial' in r1.cookies
        assert 'initial' not in r2.cookies and 'async' not in r2.cookies
        assert 'async' in s.cookies
        assert 'no_session' not in s.cookies

if __name__ == '__main__':
    unittest.main()
