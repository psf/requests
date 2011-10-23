# -*- coding: utf-8 -*-

"""
requests.auth
~~~~~~~~~~~~~

This module contains the authentication handlers for Requests.
"""

from base64 import base64

def http_basic(r, username, password):
    """Attaches HTTP Basic Authentication to the given Request object.
    Arguments should be considered non-positional.

    """
    username = str(username)
    password = str(password)

    auth_s = base64('%s:%s' % (username, password))
    r.headers['Authorization'] = ('Basic %s' % auth_s)

    return r


def http_digest(r, username, password):
    """Attaches HTTP Digest Authentication to the given Request object.
    Arguments should be considered non-positional.
    """

    r.headers