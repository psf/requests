#!/usr/bin/env python
# -*- coding: utf-8 -*-

import codecs
import os
import sys
import unittest
import random

# Path hack.
sys.path.insert(0, os.path.abspath('..'))
from requests.utils import get_environ_proxies
import requests.utils
from requests.compat import is_py3, bytes


if is_py3:
    unichr = chr
    byteschr = lambda c: bytes([c])
else:
    byteschr = chr


class UtilityTests(unittest.TestCase):
    """Tests for the JSON UTF encoding guessing code."""

    codecs = (
        'utf-8', 'utf-8-sig',
        'utf-16', 'utf-16-le', 'utf-16-be',
        'utf-32', 'utf-32-le', 'utf-32-be'
    )

    def test_guess_encoding(self):
        # Throw 4-character ASCII strings (encoded to a UTF encoding)
        # at the guess routine; it should correctly guess all codecs.
        guess = requests.utils.guess_json_utf
        for c in range(33, 127):  # printable only
            sample = unichr(c) * 4
            for codec in self.codecs:
                res = guess(sample.encode(codec))
                self.assertEqual(res, codec)

    def test_smoke_encoding(self):
        # Throw random 4-byte strings at the guess function.
        # Any guess for a UTF encoding is verified, a decode exception
        # is a test failure.
        guess = requests.utils.guess_json_utf
        for i in range(1000):
            sample = bytes().join(
                [byteschr(random.randrange(256)) for _ in range(4)])
            res = guess(sample)
            if res is not None:
                # This should decode without errors if this is *really*
                # something in this encoding. However, UTF-8 is a lot
                # more picky, so we expect errors there. UTF-16 surrogate
                # pairs also fail
                try:
                    sample.decode(res)
                except UnicodeDecodeError as e:
                    self.assertEqual(e.args[0].replace('-', '').lower(),
                                     res.replace('-', '').lower())
                    if res == 'utf-8':
                        self.assertTrue(e.args[-1], (
                            'invalid continuation byte',
                            'invalid start byte'))
                        continue
                    if res == 'utf-16':
                        self.assertEqual(e.args[-1], 'unexpected end of data')
                        self.assertTrue(sample[:2] in (
                            codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE))
                        # the second two bytes are in the range \ud800-\udfff
                        # if someone wants to add tests for that as well. I don't
                        # see the need; we are not testing UTF decoding here.
                        continue
                    raise

    def test_get_environ_proxies_respects_no_proxy(self):
        '''This test confirms that the no_proxy environment setting is
        respected by get_environ_proxies().'''

        # Store the current environment settings.
        try:
            old_http_proxy = os.environ['http_proxy']
        except KeyError:
            old_http_proxy = None

        try:
            old_no_proxy = os.environ['no_proxy']
        except KeyError:
            old_no_proxy = None

        # Set up some example environment settings.
        os.environ['http_proxy'] = 'http://www.example.com/'
        os.environ['no_proxy'] = r'localhost,.0.0.1:8080'

        # Set up expected proxy return values.
        proxy_yes = {'http': 'http://www.example.com/'}
        proxy_no = {}

        # Check that we get the right things back.
        self.assertEqual(proxy_yes,
                         get_environ_proxies('http://www.google.com/'))
        self.assertEqual(proxy_no,
                         get_environ_proxies('http://localhost/test'))
        self.assertEqual(proxy_no,
                         get_environ_proxies('http://127.0.0.1:8080/'))
        self.assertEqual(proxy_yes,
                         get_environ_proxies('http://127.0.0.1:8081/'))

        # Return the settings to what they were.
        if old_http_proxy:
            os.environ['http_proxy'] = old_http_proxy
        else:
            del os.environ['http_proxy']

        if old_no_proxy:
            os.environ['no_proxy'] = old_no_proxy
        else:
            del os.environ['no_proxy']

if __name__ == '__main__':
    unittest.main()
