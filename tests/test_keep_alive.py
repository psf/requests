#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import unittest

# Path hack.
sys.path.insert(0, os.path.abspath('..'))
import requests
import dummy_server

class KeepAliveTests(unittest.TestCase):
    server_and_proxy_port = 1234
    request_count = 2
    url = 'http://localhost:{0}'.format(server_and_proxy_port)
    proxies={'http': url}

    def setUp(self):
        self.session = requests.session()
        self.proxy_server = dummy_server.HttpServer(self.server_and_proxy_port)
        self.proxy_server.start()

    def tearDown(self):
        self.proxy_server.close()

    def test_keep_alive_with_direct_connection(self):
        self.make_requests()
        self.check_each_request_are_in_same_connection()

    def test_no_keep_alive_with_direct_connection(self):
        self.disable_keep_alive_in_session()
        self.make_requests()
        self.check_each_request_are_in_different_connection()

    def test_keep_alive_with_proxy_connection(self):
        self.make_proxy_requests()
        self.check_each_request_are_in_same_connection()

    def test_no_keep_alive_with_proxy_connection(self):
        self.disable_keep_alive_in_session()
        self.make_proxy_requests()
        self.check_each_request_are_in_different_connection()

    def make_proxy_requests(self):
        self.make_requests(self.proxies)

    def make_requests(self, proxies=None):
        for _ in range(self.request_count):
            self.session.get(self.url, proxies=proxies).text

    def check_each_request_are_in_same_connection(self):
        """Keep-alive requests open a single connection to the server."""
        self.assertEqual(self.proxy_server.connection_count, 1)

    def check_each_request_are_in_different_connection(self):
        """Keep-alive requests open a single connection to the server."""
        self.assertEqual(self.proxy_server.connection_count, self.request_count)

    def disable_keep_alive_in_session(self):
        self.session.config['keep_alive'] = False


if __name__ == '__main__':
    unittest.main()
