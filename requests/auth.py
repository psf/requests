# -*- coding: utf-8 -*-

"""
requests.auth
~~~~~~~~~~~~~

This module contains the authentication handlers for Requests.
"""

from base64 import b64encode

def http_basic(r, username, password):
    """Attaches HTTP Basic Authentication to the given Request object.
    Arguments should be considered non-positional.

    """
    username = str(username)
    password = str(password)

    auth_s = b64encode('%s:%s' % (username, password))
    r.headers['Authorization'] = ('Basic %s' % auth_s)

    return r


def http_digest(r, username, password):
    """Attaches HTTP Digest Authentication to the given Request object.
    Arguments should be considered non-positional.
    """

    r.headers


def dispatch(t):
    """Given an auth tuple, return an expanded version."""

    if not t:
        return t
    else:
        t = list(t)

    # Make sure they're passing in something.
    assert len(t) <= 2

    # If only two items are passed in, assume HTTPBasic.
    if (len(t) == 2):
        t.insert(0, 'basic')

    # Allow built-in string referenced auths.
    if isinstance(t[0], basestring):
        if t[0] in ('basic', 'forced_basic'):
            t[0] = http_basic
        elif t[0] in ('digest',):
            t[0] = http_digest

    # Return a custom callable.
    return (t[0], t[1:])


