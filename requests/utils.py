# -*- coding: utf-8 -*-

"""
requests.utils
~~~~~~~~~~~~~~

This module provides utlity functions that are used within Requests
that are also useful for external consumption.

"""


def dict_from_cookiejar(cookiejar):
    """Returns a key/value dictoinary from a CookieJar."""

    cookie_dict = {}

    for _, cookies in cookiejar._cookies.items():
        for _, cookies in cookies.items():
            for cookie in cookies.values():
                cookie_dict[cookie.name] = cookie.value

    return cookie_dict

