#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import mock
import sys
import os
sys.path.append(os.getcwd())

from requests import sessions

class RequestsSessionsUnitTests(unittest.TestCase):
    """Requests utils unit test cases."""

    def setUp(self):
        pass


    def tearDown(self):
        """Teardown."""
        pass

    def test_sessions_merge_kwargs_default_none(self):
        res = sessions.merge_kwargs('foo', None)
        self.assertEqual('foo', res)

    def test_sessions_merge_kwargs_with_basestring(self):
        local = mock.Mock(spec=basestring)
        res = sessions.merge_kwargs(local, 'default')
        self.assertEqual(local, res)

    def test_sessions_merge_kwargs_local_none(self):
        res = sessions.merge_kwargs(None, 'foo')
        self.assertEqual('foo', res)

    def test_sessions_merge_kwargs_not_a_dict(self):
        res = sessions.merge_kwargs(['foo'], [])
        self.assertEqual(['foo'], res)

    def test_sessions_merge_kwargs(self):
        res = sessions.merge_kwargs({'foo': True}, {'bar': True})
        self.assertTrue(res['foo'])
        self.assertTrue(res['bar'])

    def test_sessions_merge_kwargs_remove_none(self):
        res = sessions.merge_kwargs({'foo': None}, {'bar': True})
        self.assertTrue(res['bar'])
        self.assertTrue('foo' not in res.keys())

    @mock.patch('requests.sessions.PoolManager')
    def test_sessions_session_init(self, mock_pool):
        from requests.defaults import defaults
        mock_pool.return_value = 'pool'
        res = sessions.Session( headers=None,
                                cookies=None,
                                auth=None,
                                timeout=None,
                                proxies=None,
                                hooks=None,
                                params=None,
                                config=None)
        mock_pool.assert_called_once_with(num_pools=10, maxsize= 10)
        self.assertEqual({}, res.headers)
        self.assertEqual({}, res.cookies)
        self.assertEqual(None, res.auth)
        self.assertEqual(None, res.timeout)
        self.assertEqual({}, res.proxies)
        self.assertEqual({}, res.hooks)
        self.assertEqual({}, res.params)
        self.assertEqual(defaults, res.config)
        self.assertEqual('pool', res.poolmanager)

    @mock.patch('requests.sessions.PoolManager')
    def test_sessions_session_init_with_cookies(self, mock_pool):
        from requests.defaults import defaults
        mock_pool.return_value = 'pool'
        res = sessions.Session( headers=None,
                               cookies={'foo':'bar'},
                                auth=None,
                                timeout=None,
                                proxies=None,
                                hooks=None,
                                params=None,
                                config=None)
        mock_pool.assert_called_once_with(num_pools=10, maxsize= 10)
        self.assertEqual({}, res.headers)
        self.assertEqual(None, res.auth)
        self.assertEqual(None, res.timeout)
        self.assertEqual({}, res.proxies)
        self.assertEqual({}, res.hooks)
        self.assertEqual({}, res.params)
        self.assertEqual(defaults, res.config)
        self.assertEqual('pool', res.poolmanager)
        self.assertEqual('bar', res.cookies['foo'])

    @mock.patch('requests.sessions.Request')
    def test_sessions_request(self, mock_request):
        ret = mock.MagicMock()
        mock_request.return_value = ret
        res = sessions.Session().request( 'get', 'http://google.com',
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
                                    config=None,
                                    prefetch=False)

        self.assertEqual(ret.response, res)

    @mock.patch('requests.sessions.Request')
    def test_sessions_get(self, mock_request):
        ret = mock.MagicMock()
        mock_request.return_value = ret
        s = sessions.Session()
        res = s.get('http://google.com')
        self.assertEqual(ret.response, res)

    @mock.patch('requests.sessions.Request')
    def test_sessions_options(self, mock_request):
        ret = mock.MagicMock()
        mock_request.return_value = ret
        s = sessions.Session()
        res = s.options('http://google.com')
        self.assertEqual(ret.response, res)

    @mock.patch('requests.sessions.Request')
    def test_sessions_head(self, mock_request):
        ret = mock.MagicMock()
        mock_request.return_value = ret
        s = sessions.Session()
        res = s.head('http://google.com')
        self.assertEqual(ret.response, res)

    @mock.patch('requests.sessions.Request')
    def test_sessions_post(self, mock_request):
        ret = mock.MagicMock()
        mock_request.return_value = ret
        s = sessions.Session()
        res = s.post('http://google.com')
        self.assertEqual(ret.response, res)

    @mock.patch('requests.sessions.Request')
    def test_sessions_put(self, mock_request):
        ret = mock.MagicMock()
        mock_request.return_value = ret
        s = sessions.Session()
        res = s.put('http://google.com')
        self.assertEqual(ret.response, res)

    @mock.patch('requests.sessions.Request')
    def test_sessions_patch(self, mock_request):
        ret = mock.MagicMock()
        mock_request.return_value = ret
        s = sessions.Session()
        res = s.patch('http://google.com')
        self.assertEqual(ret.response, res)

    @mock.patch('requests.sessions.Request')
    def test_sessions_delete(self, mock_request):
        ret = mock.MagicMock()
        mock_request.return_value = ret
        s = sessions.Session()
        res = s.delete('http://google.com')
        self.assertEqual(ret.response, res)





if __name__ == '__main__':
    unittest.main()
