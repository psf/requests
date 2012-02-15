#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Path hack.
import sys, os
sys.path.insert(0, os.path.abspath('..'))

import sys
import unittest

from requests import async
import envoy

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


if __name__ == '__main__':
    unittest.main()
