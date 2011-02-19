# -*- coding: utf-8 -*-

"""
    requests.core
    ~~~~~~~~~~~~~

    This module implements the main Requests system.

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

__all__ = ['Request', 'Response', 'request', 'get', 'head', 'post', 'put', 'delete', 'add_autoauth', 'AUTOAUTHS',
           'RequestException', 'AuthenticationError', 'URLRequired', 'InvalidMethod', 'HTTPError']
__title__ = 'requests'
__version__ = '0.0.1'
__build__ = 0x000001
__author__ = 'Dj Gilcrease'
__license__ = 'ISC'
__copyright__ = 'Copyright 2011 Dj Gilcrease'
