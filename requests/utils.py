# -*- coding: utf-8 -*-

"""
requests.utils
~~~~~~~~~~~~~~

This module provides utlity functions that are used within Requests
that are also useful for external consumption.

"""

import Cookie
import cookielib


def dict_from_cookiejar(cookiejar):
    """Returns a key/value dictionary from a CookieJar."""

    cookie_dict = {}

    for _, cookies in cookiejar._cookies.items():
        for _, cookies in cookies.items():
            for cookie in cookies.values():
                cookie_dict[cookie.name] = cookie.value

    return cookie_dict


def cookiejar_from_dict(cookie_dict, domain=None):
    """Returns a CookieJar from a key/value dictoinary."""

    # create cookiejar
    cj = cookielib.CookieJar()

    for k, v in cookie_dict.items():

        # create cookie
        ck = Cookie.SimpleCookie()
        ck.name = v
        ck.expires = 0
        ck.path = '/'
        ck.domain = domain

        # add cookie to cookiejar
        cj.set_cookie(ck)

    return cj

