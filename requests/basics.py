# -*- coding: utf-8 -*-
"""
requests.basics
~~~~~~~~~~~~~~~

This modules covers the basics.
"""

import chardet

import sys

# ---------
# Specifics
# ---------
from urllib.parse import (
    urlparse,
    urlunparse,
    urljoin,
    urlsplit,
    urlencode,
    quote,
    unquote,
    quote_plus,
    unquote_plus,
    urldefrag,
)
from urllib.request import (
    parse_http_list,
    getproxies,
    proxy_bypass,
    proxy_bypass_environment,
    getproxies_environment,
)
from http import cookiejar as cookielib
from http.cookies import Morsel
from io import StringIO
from collections import OrderedDict

builtin_str = str  # type: ignore
str = str  # type: ignore
bytes = bytes  # type: ignore
basestring = (str, bytes)
numeric_types = (int, float)
integer_types = (int,)
