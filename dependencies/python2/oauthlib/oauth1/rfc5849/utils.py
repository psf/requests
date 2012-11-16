# -*- coding: utf-8 -*-

"""
oauthlib.utils
~~~~~~~~~~~~~~

This module contains utility methods used by various parts of the OAuth
spec.
"""

import string
import urllib2

from oauthlib.common import quote, unquote

UNICODE_ASCII_CHARACTER_SET = (string.ascii_letters.decode('ascii') +
    string.digits.decode('ascii'))


def filter_params(target):
    """Decorator which filters params to remove non-oauth_* parameters

    Assumes the decorated method takes a params dict or list of tuples as its
    first argument.
    """
    def wrapper(params, *args, **kwargs):
        params = filter_oauth_params(params)
        return target(params, *args, **kwargs)

    wrapper.__doc__ = target.__doc__
    return wrapper


def filter_oauth_params(params):
    """Removes all non oauth parameters from a dict or a list of params."""
    is_oauth = lambda kv: kv[0].startswith(u"oauth_")
    if isinstance(params, dict):
        return filter(is_oauth, params.items())
    else:
        return filter(is_oauth, params)


def escape(u):
    """Escape a unicode string in an OAuth-compatible fashion.

    Per `section 3.6`_ of the spec.

    .. _`section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6

    """
    if not isinstance(u, unicode):
        raise ValueError('Only unicode objects are escapable.')
    # Letters, digits, and the characters '_.-' are already treated as safe
    # by urllib.quote(). We need to add '~' to fully support rfc5849.
    return quote(u, safe='~')


def unescape(u):
    if not isinstance(u, unicode):
        raise ValueError('Only unicode objects are unescapable.')
    return unquote(u)


def urlencode(query):
    """Encode a sequence of two-element tuples or dictionary into a URL query string.

    Operates using an OAuth-safe escape() method, in contrast to urllib.urlencode.
    """
    # Convert dictionaries to list of tuples
    if isinstance(query, dict):
        query = query.items()
    return u"&".join([u'='.join([escape(k), escape(v)]) for k, v in query])


def parse_keqv_list(l):
    """A unicode-safe version of urllib2.parse_keqv_list"""
    encoded_list = [u.encode('utf-8') for u in l]
    encoded_parsed = urllib2.parse_keqv_list(encoded_list)
    return dict((k.decode('utf-8'),
        v.decode('utf-8')) for k, v in encoded_parsed.items())


def parse_http_list(u):
    """A unicode-safe version of urllib2.parse_http_list"""
    encoded_str = u.encode('utf-8')
    encoded_list = urllib2.parse_http_list(encoded_str)
    return [s.decode('utf-8') for s in encoded_list]


def parse_authorization_header(authorization_header):
    """Parse an OAuth authorization header into a list of 2-tuples"""
    auth_scheme = u'OAuth '
    if authorization_header.startswith(auth_scheme):
        authorization_header = authorization_header.replace(auth_scheme, u'', 1)
    items = parse_http_list(authorization_header)
    try:
        return parse_keqv_list(items).items()
    except ValueError:
        raise ValueError('Malformed authorization header')
