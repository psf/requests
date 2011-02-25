# -*- coding: utf-8 -*-

"""
    requests.async
    ~~~~~~~~~~~~~~

    This module implements the main Requests system, after monkey-patching
    the urllib2 module with eventlet or gevent..

    :copyright: (c) 2011 by Kenneth Reitz.
    :license: ISC, see LICENSE for more details.
"""


from __future__ import absolute_import

import urllib
import urllib2

from urllib2 import HTTPError


try:
    import eventlet
    eventlet.monkey_patch()
except ImportError:
    pass

if not 'eventlet' in locals():
    try:
        from gevent import monkey
        monkey.patch_all()
    except ImportError:
        pass


if not 'eventlet' in locals():
    raise ImportError('No Async adaptations of urllib2 found!')


from .core import *


__all__ = [
    'Request', 'Response', 'request', 'get', 'head', 'post', 'put', 'delete', 
    'auth_manager', 'AuthObject','RequestException', 'AuthenticationError', 
    'URLRequired', 'InvalidMethod', 'HTTPError'
]
