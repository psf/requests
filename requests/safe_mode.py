# -*- coding: utf-8 -*-

"""
requests.safe_mode
~~~~~~~~~~~~

This module contains a decorator that implements safe_mode.

:copyright: (c) 2012 by Kenneth Reitz.
:license: ISC, see LICENSE for more details.

"""

from .models import Response
from .packages.urllib3.response import HTTPResponse
from .exceptions import RequestException, ConnectionError, HTTPError
import socket

def catch_exceptions_if_in_safe_mode(function):
    """New implementation of safe_mode. We catch all exceptions at the API level
    and then return a blank Response object with the error field filled. This decorator
    wraps request() in api.py.
    """
    
    def wrapped(method, url, **kwargs):
        # if save_mode, we catch exceptions and fill error field
        if (kwargs.get('config') and kwargs.get('config').get('safe_mode')) or (kwargs.get('session') 
                                            and kwargs.get('session').config.get('safe_mode')):
            try:
                return function(method, url, **kwargs)
            except (RequestException, ConnectionError, HTTPError, socket.timeout) as e:
                r = Response()
                r.error = e
                r.raw = HTTPResponse() # otherwise, tests fail
                r.status_code = 0 # with this status_code, content returns None
                return r
        return function(method, url, **kwargs)
    return wrapped
