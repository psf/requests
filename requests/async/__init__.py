# -*- coding: utf-8 -*-

"""
requests.async
~~~~~~~~~~~~~~

This module contains an asynchronous replica of ``requests.api``, powered
by gevent or eventlet. All API methods return a ``Request`` instance (as opposed to
``Response``). A list of requests can be sent with ``map()``.
"""

from .. import api
from ..hooks import dispatch_hook


__all__ = ('get', 'head', 'post', 'put', 'patch', 'delete', 'request')


def _patched(f):
    """Patches a given API function to not send."""

    def wrapped(*args, **kwargs):
        return f(*args, return_response=False, **kwargs)

    return wrapped


def _send(r, pools=None):
    """Sends a given Request object."""

    if pools:
        r._pools = pools

    r.send()

    # Post-request hook.
    r = dispatch_hook('post_request', r.hooks, r)

    # Response manipulation hook.
    r.response = dispatch_hook('response', r.hooks, r.response)

    return r.response


# Patched requests.api functions.
get = _patched(api.get)
head = _patched(api.head)
post = _patched(api.post)
put = _patched(api.put)
patch = _patched(api.patch)
delete = _patched(api.delete)
request = _patched(api.request)

