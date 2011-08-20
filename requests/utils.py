# -*- coding: utf-8 -*-

"""
requests.utils
~~~~~~~~~~~~~~

This module provides utlity functions that are used within Requests
that are also useful for external consumption.

"""

import cgi
import cookielib
import re


def dict_from_cookiejar(cookiejar):
    """Returns a key/value dictionary from a CookieJar."""

    cookie_dict = {}

    for _, cookies in cookiejar._cookies.items():
        for _, cookies in cookies.items():
            for cookie in cookies.values():
                # print cookie
                cookie_dict[cookie.name] = cookie.value

    return cookie_dict


def cookiejar_from_dict(cookie_dict):
    """Returns a CookieJar from a key/value dictionary."""

    # return cookiejar if one was passed in
    if isinstance(cookie_dict, cookielib.CookieJar):
        return cookie_dict

    # create cookiejar
    cj = cookielib.CookieJar()

    cj = add_dict_to_cookiejar(cj, cookie_dict)

    return cj


def add_dict_to_cookiejar(cj, cookie_dict):
    """Returns a CookieJar from a key/value dictionary."""

    for k, v in cookie_dict.items():

        cookie = cookielib.Cookie(
            version=0,
            name=k,
            value=v,
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
            rfc2109=False
        )

        # add cookie to cookiejar
        cj.set_cookie(cookie)

    return cj


def get_encodings_from_content(content):
    """Returns encodings from given content string."""

    charset_re = re.compile(r'<meta.*?charset=["\']*(.+?)["\'>]', flags=re.I)

    return charset_re.findall(content)



def get_encoding_from_headers(headers):
    """Returns encodings from given HTTP Header Dict."""

    content_type = headers.get('content-type')
    content_type, params = cgi.parse_header(content_type)

    if 'charset' in params:
        return params['charset'].strip("'\"")


def get_unicode_from_response(r):
    """Returns the requested content back in unicode.

    Tried:
    1. charset from content-type
    2. every encodings from <meta ... charset=XXX>
    3. fall back and replace all unicode characters
    """

    tried_encodings = []

    # Try charset from content-type
    encoding = get_encoding_from_headers(r.headers)

    if encoding:
        try:
            print '!'
            return unicode(r.content, encoding)
        except UnicodeError:
            tried_encodings.append(encoding)

    # Try every encodings from <meta ... charset=XXX>
    encodings = get_encodings_from_content(r.content)

    for encoding in encodings:
        if encoding in tried_encodings:
            continue
        try:

            return unicode(r.content, encoding)
        except (UnicodeError, TypeError):
            tried_encodings.append(encoding)

    # Fall back:
    try:
        return unicode(r.content, encoding, errors='replace')
    except TypeError:
        return r.content
