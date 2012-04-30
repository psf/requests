#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os
import json
import unittest

# Path hack.
sys.path.insert(0, os.path.abspath('..'))
import requests

class HTTPSTest(unittest.TestCase):
    """Smoke test for https functionality."""

    smoke_url = "https://github.com"

    def perform_smoke_test(self, verify=False):
        result = requests.get(self.smoke_url, verify=verify)
        self.assertEqual(result.status_code, 200)

    def test_smoke(self):
        """Smoke test without verification."""
        self.perform_smoke_test(verify=False)

    def test_smoke_verified(self):
        """Smoke test with SSL verification."""
        self.perform_smoke_test(verify=True)


if __name__ == '__main__':
    unittest.main()
