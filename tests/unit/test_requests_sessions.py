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

if __name__ == '__main__':
    unittest.main()
