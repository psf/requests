# -*- coding: utf-8 -*-

"""
oreos.core
~~~~~~~~~~

The creamy white center.
"""

from .structures import MultiDict
from .monkeys import SimpleCookie


def dict_from_string(s):
    """Returns a MultiDict with Cookies."""

    cookies = MultiDict()

    c = SimpleCookie()
    c.load(s)

    for k,v in c.items():
        cookies.add(k, v.value)

    return cookies