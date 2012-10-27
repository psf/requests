#!/usr/bin/env python
# -*- coding: utf-8 -*-

import codecs
import os
import sys
import unittest
import random

# Path hack.
sys.path.insert(0, os.path.abspath('..'))
import requests.utils
from requests.compat import is_py3, bytes


if is_py3:
    unichr = chr
    byteschr = lambda c: bytes([c])
else:
    byteschr = chr


class GuessJSONUTFTests(unittest.TestCase):
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

if __name__ == '__main__':
    unittest.main()
