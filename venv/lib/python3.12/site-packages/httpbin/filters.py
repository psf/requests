# -*- coding: utf-8 -*-

"""
httpbin.filters
~~~~~~~~~~~~~~~

This module provides response filter decorators.
"""

import gzip as gzip2
import zlib

import brotlicffi as _brotli

from six import BytesIO
from decimal import Decimal
from time import time as now

from decorator import decorator
from flask import Flask, Response


app = Flask(__name__)


@decorator
def x_runtime(f, *args, **kwargs):
    """X-Runtime Flask Response Decorator."""

    _t0 = now()
    r = f(*args, **kwargs)
    _t1 = now()
    r.headers['X-Runtime'] = '{0}s'.format(Decimal(str(_t1 - _t0)))

    return r


@decorator
def gzip(f, *args, **kwargs):
    """GZip Flask Response Decorator."""

    data = f(*args, **kwargs)

    if isinstance(data, Response):
        content = data.data
    else:
        content = data

    gzip_buffer = BytesIO()
    gzip_file = gzip2.GzipFile(
        mode='wb',
        compresslevel=4,
        fileobj=gzip_buffer
    )
    gzip_file.write(content)
    gzip_file.close()

    gzip_data = gzip_buffer.getvalue()

    if isinstance(data, Response):
        data.data = gzip_data
        data.headers['Content-Encoding'] = 'gzip'
        data.headers['Content-Length'] = str(len(data.data))

        return data

    return gzip_data


@decorator
def deflate(f, *args, **kwargs):
    """Deflate Flask Response Decorator."""

    data = f(*args, **kwargs)

    if isinstance(data, Response):
        content = data.data
    else:
        content = data

    deflater = zlib.compressobj()
    deflated_data = deflater.compress(content)
    deflated_data += deflater.flush()

    if isinstance(data, Response):
        data.data = deflated_data
        data.headers['Content-Encoding'] = 'deflate'
        data.headers['Content-Length'] = str(len(data.data))

        return data

    return deflated_data


@decorator
def brotli(f, *args, **kwargs):
    """Brotli Flask Response Decorator"""

    data = f(*args, **kwargs)

    if isinstance(data, Response):
        content = data.data
    else:
        content = data

    deflated_data = _brotli.compress(content)

    if isinstance(data, Response):
        data.data = deflated_data
        data.headers['Content-Encoding'] = 'br'
        data.headers['Content-Length'] = str(len(data.data))

        return data

    return deflated_data
