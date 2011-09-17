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


    @mock.patch('requests.api.dispatch_hook')
    @mock.patch('requests.api.Request')
    @mock.patch('requests.api.cookiejar_from_dict')
    def test_request(self, mock_cjar, mock_request, mock_hook):
        args = dict(
                    method = None,
                    url = None,
                    data = None,
                    params = None,
                    headers = None,
                    cookiejar = None,
                    files = None,
                    auth = None,
                    timeout = 1,
                    allow_redirects = None,
                    proxies = None,
                   )
        hooks = {'args': args, 'pre_request': mock_request,
                 'post_request': mock_request, 'response': 'response'}
        sideeffect = lambda x,y,z: hooks[x]
        mock_cjar.return_value = None
        mock_request.send = mock.Mock(return_value={})
        mock_request.response = "response"
        mock_hook.side_effect = sideeffect

        r = requests.request('get','http://google.com')


        mock_cjar.assert_called_once_with({})
        mock_hook.assert_called__with('args', None, args)
        mock_request.assert_called_once_with(**args)
        mock_hook.assert_called__with('pre_request', None, mock_request)
        mock_request.send.assert_called_once_with()
        mock_hook.assert_called__with('post_request', None, mock_request)
        mock_hook.assert_called__with('response', None, mock_request)
        self.assertEqual(r, "response")



    @mock.patch('requests.api.request')
    def test_http_get(self, mock_request):
        mock_request.return_value = Response()
        requests.get('http://google.com')
        mock_request.assert_called_once_with('get', 'http://google.com',
                                             allow_redirects= True)

    @mock.patch('requests.api.request')
    def test_http_get_with_kwargs(self, mock_request):
        mock_request.return_value = Response()
        requests.get('http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")
        mock_request.assert_called_once_with('get', 'http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")

    @mock.patch('requests.api.request')
    def test_http_head(self, mock_request):
        mock_request.return_value = Response()
        requests.head('http://google.com')
        mock_request.assert_called_once_with('head', 'http://google.com',
                                             allow_redirects= True)

    @mock.patch('requests.api.request')
    def test_http_head_with_kwargs(self, mock_request):
        mock_request.return_value = Response()
        requests.head('http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")
        mock_request.assert_called_once_with('head', 'http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")

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
