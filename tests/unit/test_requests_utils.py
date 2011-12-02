#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import mock
import sys
import os
sys.path.append(os.getcwd())

from requests import utils

class RequestsUtilsUnitTests(unittest.TestCase):
    """Requests utils unit test cases."""

    def setUp(self):
        pass


    def tearDown(self):
        """Teardown."""
        pass

    def test_utils_guess_filename(self):
        obj = mock.MagicMock()
        obj.name = "Jean-Luc"
        res = utils.guess_filename(obj)
        self.assertEqual('Jean-Luc',res)

    def test_utils_guess_filename_with_front_via(self):
        obj = mock.MagicMock()
        obj.name = "<Jean-Luc"
        res = utils.guess_filename(obj)
        self.assertEqual(None,res)

    def test_utils_guess_filename_with_back_via(self):
        obj = mock.MagicMock()
        obj.name = "Jean-Luc>"
        res = utils.guess_filename(obj)
        self.assertEqual(None,res)

    def test_utils_parse_list_headers(self):
        res = utils.parse_list_header('token, "quoted value"')
        self.assertEqual(['token', 'quoted value'], res)

    def test_utils_parse_dict_headers(self):
        d = utils.parse_dict_header('foo="is a fish", bar="as well",no_val')
        self.assertTrue(type(d) is dict)
        self.assertEqual([('bar', 'as well'),
                          ('foo', 'is a fish'),
                          ('no_val', None)],
                         sorted(d.items()))

    def test_utils_unquote_header_value(self):
        res = utils.unquote_header_value('"foo"')
        self.assertEqual('foo', res)

    def test_utils_unquote_header_value_with_slashes(self):
        res = utils.unquote_header_value('"foo\\\\bar"')
        self.assertEqual('foo\\bar', res)

    def test_utils_unquote_header_value_with_filename(self):
        res = utils.unquote_header_value('"\\\\bar"', is_filename=True)
        self.assertEqual('\\\\bar', res)

    def test_utils_header_expand(self):
        res = utils.header_expand(
        {'text/x-dvi': {'q': '.8', 'mxb': '100000', 'mxt': '5.0'}, 'text/x-c':
         {}})
        self.assertEqual("text/x-c; text/x-dvi; q=.8; mxt=5.0; mxb=100000",
                         res)

    def test_utils_header_expand_string(self):
        res = utils.header_expand('foo')
        self.assertEqual('foo', res)

    # The substitution of os.path.exists should be done with a mock here,
    # however when I tried it, some strange behaviour in combination with
    # coverage appeared. At least with the lambdas it works.
    @mock.patch('__builtin__.open')
    def test_utils_randombytes_urandom(self, mock_open):
        try:
            old_exists = utils.os.path.exists
            utils.os.path.exists = lambda x: True
            mock_file = mock.MagicMock()
            mock_file.read.return_value = 'random'
            mock_open.return_value = mock_file
            r = utils.randombytes(5)
            mock_open.assert_called_once_with('/dev/urandom')
            mock_file.read.assert_called_once_with(5)
            mock_file.close.assert_called_once()
            self.assertEqual('random', r)
        finally:
            utils.os.path.exists = old_exists

    @mock.patch('requests.utils.random')
    def test_utils_randombytes_no_urandom(self, mock_random):
        try:
            old_exists = utils.os.path.exists
            utils.os.path.exists = lambda x: False
            mock_random.randrange.return_value = 97
            r = utils.randombytes(5)
            self.assertEqual(5, mock_random.randrange.call_count)
            self.assertEqual('aaaaa', r)
        finally:
            utils.os.path.exists = old_exists

    def test_utils_dict_from_cookiejar(self):
        basejar = mock.MagicMock()
        basejar.name = "foo"
        basejar.value = "bar"
        superjar = mock.MagicMock()
        superjar.values.return_value = [basejar]
        ssuperjar = mock.MagicMock()
        ssuperjar.items.return_value = [[None, superjar]]
        cj = mock.MagicMock()
        cj._cookies.items.return_value = [[None, ssuperjar]]


        res = utils.dict_from_cookiejar(cj)
        self.assertTrue(type(res) is dict)
        self.assertEqual(1, len(res.keys()))
        self.assertTrue('foo' in res.keys())
        self.assertEqual('bar', res['foo'])

    def test_utils_cookiejar_from_dict_with_cookiejar(self):
        import cookielib
        cd = mock.Mock(spec=cookielib.CookieJar)
        res = utils.cookiejar_from_dict(cd)
        self.assertEqual(cd, res)

    @mock.patch('requests.utils.cookielib.Cookie')
    def test_utils_add_dict_to_cookiejar(self, mock_cookie):
        cj = mock.Mock()
        mock_cookie.return_value = True

        res = utils.add_dict_to_cookiejar(cj, {'foo': 'bar'})
        cj.set_cookie.assert_called_once_with(True)
        mock_cookie.assert_called_once_with(
                                            version=0,
                                            name='foo',
                                            value='bar',
                                            port=None,
                                            port_specified=False,
                                            domain='',
                                            domain_specified=False,
                                            domain_initial_dot=False,
                                            path='/',
                                            path_specified=True,
                                            secure=False,
                                            expires=None,
                                            discard=True,
                                            comment=None,
                                            comment_url=None,
                                            rest={'HttpOnly': None},
                                            rfc2109=False )
        self.assertEqual(cj, res)


    def test_utils_get_encodings_from_content(self):
        res = utils.get_encodings_from_content('<meta charset="foo">')
        self.assertEqual(['foo'], res)

    def test_utils_get_encodings_from_content_multi_occurence(self):
        s = """<meta charset="foo">
               <meta charset="bar">
            """
        res = utils.get_encodings_from_content(s)
        self.assertEqual(['foo', 'bar'], res)

    @mock.patch('requests.utils.cgi.parse_header')
    def test_utils_get_encoding_from_headers(self, mock_parse):
        mock_parse.return_value = None, {'charset': "'UTF-8'"}
        header = {'content-type': 'pizza'}
        res = utils.get_encoding_from_headers(header)

        mock_parse.assert_called_once_with('pizza')
        self.assertEqual('UTF-8', res)

    def test_utils_get_encoding_from_headers_no_content_type(self):
        res = utils.get_encoding_from_headers({})
        self.assertEqual(None, res)

    @mock.patch('requests.utils.cgi.parse_header')
    def test_utils_get_encoding_from_headers_no_charset(self, mock_parse):
        mock_parse.return_value = None, {}
        header = {'content-type': 'pizza'}
        res = utils.get_encoding_from_headers(header)

        mock_parse.assert_called_once_with('pizza')
        self.assertEqual(None, res)


if __name__ == '__main__':
    unittest.main()
