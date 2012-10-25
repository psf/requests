#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import unittest
import random

# Path hack.
sys.path.insert(0, os.path.abspath('..'))
import requests.utils
from requests.compat import is_py3, bytes


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
        unichr = chr if is_py3 else __builtins__.unichr
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
        chr = (lambda c: bytes([c])) if is_py3 else __builtins__.chr
        guess = requests.utils.guess_json_utf
        for i in range(1000):
            sample = bytes().join(
                [chr(random.randrange(256)) for _ in range(4)])
            res = guess(sample)
            if res is not None and res != 'utf-8':
                # This should decode without errors if this is *really*
                # something in this encoding. Skip UTF-8, it is more
                # picky about valid data.
                sample.decode(res)


if __name__ == '__main__':
    unittest.main()
