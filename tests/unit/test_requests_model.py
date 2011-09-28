#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import mock
import sys
import os
sys.path.append(os.getcwd())

from requests import models
from requests.monkeys import HTTPBasicAuthHandler, HTTPForcedBasicAuthHandler,\
                             HTTPDigestAuthHandler, HTTPRedirectHandler
import urllib2

class RequestsAPIUnitTests(unittest.TestCase):
    """Requests API unit test cases."""

    def setUp(self):
        pass


    def tearDown(self):
        """Teardown."""
        pass

    def test_AuthObject_defaults(self):
        auth = models.AuthObject('Skeletor', 'mumble')
        self.assertEqual('Skeletor', auth.username)
        self.assertEqual('mumble', auth.password)
        self.assertEqual(HTTPForcedBasicAuthHandler, auth.handler)
        self.assertEqual(None, auth.realm)

    def test_AuthObject_forcedbasic_with_realm(self):
        auth = models.AuthObject('Skeletor', 'mumble', 'forced_basic',
                                 'Snake Mountain')
        self.assertEqual('Skeletor', auth.username)
        self.assertEqual('mumble', auth.password)
        self.assertEqual(HTTPForcedBasicAuthHandler, auth.handler)
        self.assertEqual('Snake Mountain', auth.realm)

    def test_AuthObject_basic_with_realm(self):
        auth = models.AuthObject('Skeletor', 'mumble', 'basic',
                                 'Snake Mountain')
        self.assertEqual('Skeletor', auth.username)
        self.assertEqual('mumble', auth.password)
        self.assertEqual(HTTPBasicAuthHandler, auth.handler)
        self.assertEqual('Snake Mountain', auth.realm)

    def test_AuthObject_digest_with_realm(self):
        auth = models.AuthObject('Skeletor', 'mumble', 'digest',
                                 'Snake Mountain')
        self.assertEqual('Skeletor', auth.username)
        self.assertEqual('mumble', auth.password)
        self.assertEqual(HTTPDigestAuthHandler, auth.handler)
        self.assertEqual('Snake Mountain', auth.realm)

    def test_AuthObject_proxybasic_with_realm(self):
        auth = models.AuthObject('Skeletor', 'mumble', 'proxy_basic',
                                 'Snake Mountain')
        self.assertEqual('Skeletor', auth.username)
        self.assertEqual('mumble', auth.password)
        self.assertEqual(urllib2.ProxyBasicAuthHandler, auth.handler)
        self.assertEqual('Snake Mountain', auth.realm)

    def test_AuthObject_proxdigest_with_realm(self):
        auth = models.AuthObject('Skeletor', 'mumble', 'proxy_digest',
                                 'Snake Mountain')
        self.assertEqual('Skeletor', auth.username)
        self.assertEqual('mumble', auth.password)
        self.assertEqual(urllib2.ProxyDigestAuthHandler, auth.handler)
        self.assertEqual('Snake Mountain', auth.realm)

    def test_AuthObject_with_bad_handler(self):
        auth = models.AuthObject('Skeletor', 'mumble', 'panthor',
                                 'Snake Mountain')
        self.assertEqual('Skeletor', auth.username)
        self.assertEqual('mumble', auth.password)
        self.assertEqual(HTTPForcedBasicAuthHandler, auth.handler)
        self.assertEqual('Snake Mountain', auth.realm)

if __name__ == '__main__':
    unittest.main()
