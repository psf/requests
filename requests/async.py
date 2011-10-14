# -*- coding: utf-8 -*-

"""
requests.async
~~~~~~~~~~~~~~

This module contains an asynchronous replica of ``requests.api``, powered
by gevent. All API methods return a ``Request`` instance (as opposed to
``Response``). A list of requests can be sent with ``map()``.
"""

try:
    import gevent
    from gevent import monkey as curious_george
except ImportError:
    raise RuntimeError('Gevent is required for requests.async.')

# Monkey-patch.
curious_george.patch_all(thread=False)

from . import api
from .hooks import dispatch_hook
from .packages.urllib3.poolmanager import PoolManager


__all__ = (
    'map',
    'get', 'head', 'post', 'put', 'patch', 'delete', 'request'
)


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


def map(requests, keep_alive=False):
    """Concurrently converts a list of Requests to Responses.

    :param requests: a collection of Request objects.
    :param keep_alive: If True, HTTP Keep-Alive will be used.
    """

    if keep_alive:
        pools = PoolManager(num_pools=len(requests), maxsize=1)
    else:
        pools = None

    jobs = [gevent.spawn(_send, r, pools=pools) for r in requests]
    gevent.joinall(jobs)

    return [r.response for r in requests]




