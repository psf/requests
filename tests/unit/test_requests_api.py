#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import mock
import sys
import os
sys.path.append(os.getcwd())

try:
    import omnijson as json
except ImportError:
    import json

import requests
from requests.models import Response

class RequestsAPIUnitTests(unittest.TestCase):
    """Requests API unit test cases."""

    def setUp(self):
        pass


    def tearDown(self):
        """Teardown."""
        pass


    @mock.patch('requests.api.request')
    def test_http_get(self, mock_request):
        mock_request.return_value = Response()
        requests.get('http://google.com')
        mock_request.assert_called_once_with('get', 'http://google.com',
                                             allow_redirects= True)

    @mock.patch('requests.api.request')
    def test_http_head(self, mock_request):
        mock_request.return_value = Response()
        requests.head('http://google.com')
        mock_request.assert_called_once_with('head', 'http://google.com',
                                             allow_redirects= True)

    @mock.patch('requests.api.request')
    def test_http_post(self, mock_request):
        mock_request.return_value = Response()
        requests.post('http://google.com', {})
        mock_request.assert_called_once_with('post', 'http://google.com',
                                              data= {})

    @mock.patch('requests.api.request')
    def test_http_put(self, mock_request):
        mock_request.return_value = Response()
        requests.put('http://google.com', {})
        mock_request.assert_called_once_with('put', 'http://google.com',
                                             data= {})

    @mock.patch('requests.api.request')
    def test_http_patch(self, mock_request):
        mock_request.return_value = Response()
        requests.patch('http://google.com', {})
        mock_request.assert_called_once_with('patch', 'http://google.com',
                                             data= {})

    @mock.patch('requests.api.request')
    def test_http_delete(self, mock_request):
        mock_request.return_value = Response()
        requests.delete('http://google.com')
        mock_request.assert_called_once_with('delete', 'http://google.com')

if __name__ == '__main__':
    unittest.main()
