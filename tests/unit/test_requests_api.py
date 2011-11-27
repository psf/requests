#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import mock
import sys
import os
sys.path.append(os.getcwd())

import requests
from requests.models import Response

class RequestsAPIUnitTests(unittest.TestCase):
    """Requests API unit test cases."""

    def setUp(self):
        pass


    def tearDown(self):
        """Teardown."""
        pass


    def test_request(self):
        mock_session = mock.Mock()
        mock_request = mock.Mock()
        mock_request.return_value = "response"
        mock_session.request = mock_request
        r = requests.request('get','http://google.com',
                             params=None,
                             data=None,
                             headers=None,
                             cookies=None,
                             files=None,
                             auth=None,
                             timeout=None,
                             allow_redirects=False,
                             proxies=None,
                             hooks=None,
                             return_response=True,
                             prefetch=False,
                             session=mock_session,
                             config=None)

        mock_request.assert_called__with('get',
                                         'http://google.com',
                                         None,
                                         None,
                                         None,
                                         None,
                                         None,
                                         None,
                                         None,
                                         False,
                                         None,
                                         None,
                                         True,
                                         None)
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

    @mock.patch('requests.api.request')
    def test_http_post(self, mock_request):
        mock_request.return_value = Response()
        requests.post('http://google.com', {})
        mock_request.assert_called_once_with('post', 'http://google.com',
                                              data= {})

    @mock.patch('requests.api.request')
    def test_http_post_with_kwargs(self, mock_request):
        mock_request.return_value = Response()
        requests.post('http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")
        mock_request.assert_called_once_with('post', 'http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")


    @mock.patch('requests.api.request')
    def test_http_put(self, mock_request):
        mock_request.return_value = Response()
        requests.put('http://google.com', {})
        mock_request.assert_called_once_with('put', 'http://google.com',
                                             data= {})

    @mock.patch('requests.api.request')
    def test_http_put_with_kwargs(self, mock_request):
        mock_request.return_value = Response()
        requests.put('http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")
        mock_request.assert_called_once_with('put', 'http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")


    @mock.patch('requests.api.request')
    def test_http_patch(self, mock_request):
        mock_request.return_value = Response()
        requests.patch('http://google.com', {})
        mock_request.assert_called_once_with('patch', 'http://google.com',
                                             data= {})

    @mock.patch('requests.api.request')
    def test_http_patch_with_kwargs(self, mock_request):
        mock_request.return_value = Response()
        requests.patch('http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")
        mock_request.assert_called_once_with('patch', 'http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")

    @mock.patch('requests.api.request')
    def test_http_delete(self, mock_request):
        mock_request.return_value = Response()
        requests.delete('http://google.com')
        mock_request.assert_called_once_with('delete', 'http://google.com')

    @mock.patch('requests.api.request')
    def test_http_delete_with_kwargs(self, mock_request):
        mock_request.return_value = Response()
        requests.delete('http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")
        mock_request.assert_called_once_with('delete', 'http://google.com',
                     params="params", data="data", headers="headers",
                     cookies="cookies",
                     files="files", auth="auth", timeout="timeout",
                     allow_redirects=False,
                     proxies="proxies", hooks="hooks")


if __name__ == '__main__':
    unittest.main()
