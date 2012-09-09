#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import fudge
import requests


class TestRequestsWithFudge(unittest.TestCase):

    @fudge.patch('requests.sessions.PoolManager',
        'requests.models.extract_cookies_to_jar')
    def test_requests_build_response(self, fake_pm, fake_c):
        """
        Fake HTTPResponse has a header attr set to None.
        This is equivalent to the getattr(resp, 'headers', None).

        TypeError is raised.
        """
        fake_r = fake_pm.is_callable().returns_fake().is_a_stub().\
            expects('connection_from_url').returns_fake().\
            expects('urlopen').returns_fake().has_attr(status=200, headers=None)
        assert 'headers' in fake_r._attributes
        assert fake_r._attributes['headers'] is None,\
            "Fake Response headers value is incorrect"

        # fudge extract_cookies_to_jar so i don't have
        # to worry bout _original_msg attr
        fake_c.is_callable()
        try:
            requests.get('http://httpbin.org')
            assert False, 'Failed to raise exception'
        except TypeError as e:
            assert e.args[0] == "'NoneType' object is not iterable"
        except Exception:
            assert False, "Unexpected exception"

        """
        Fake HTTPResponse lacks headers attr
        so default {} will be returned.
        """
        fake_r = fake_pm.is_callable().returns_fake().is_a_stub().\
            expects('connection_from_url').returns_fake().\
            expects('urlopen').returns_fake().has_attr(status=200)
        assert 'headers' not in fake_r._attributes, "Fake Response had headers"

        requests.get('http://httpbin.org')

if __name__ == '__main__':
    unittest.main()
