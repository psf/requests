#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import unittest

# Path hack.
sys.path.insert(0, os.path.abspath('..'))
import requests


class HTTPSProxyTest(unittest.TestCase):
    """Smoke test for https functionality."""

    smoke_url = "https://github.com"

    def test_empty_https_proxy(self):
        proxy = {"https": ""}
        result = requests.get(self.smoke_url, verify=False, proxies=proxy)
        self.assertEqual(result.status_code, 200)

    def test_empty_http_proxy(self):
        proxy = {"http": ""}
        result = requests.get(self.smoke_url, proxies=proxy)
        self.assertEqual(result.status_code, 200)

if __name__ == '__main__':
    unittest.main()
