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


__all__ = (
    'map',
    'get', 'head', 'post', 'put', 'patch', 'delete', 'request'
)


def patched(f):
    """Patches a given API function to not send."""

    def wrapped(*args, **kwargs):

        kwargs['return_response'] = False

        return f(*args, **kwargs)

    return wrapped


def send(r, pools=None):
    """Sends a given Request object."""

    if pools:
        r._pools = pools

    r.send()

    return r.response


# Patched requests.api functions.
get = patched(api.get)
head = patched(api.head)
post = patched(api.post)
put = patched(api.put)
patch = patched(api.patch)
delete = patched(api.delete)
request = patched(api.request)


def map(requests, prefetch=True):
    """Concurrently converts a list of Requests to Responses.

    :param requests: a collection of Request objects.
    :param prefetch: If False, the content will not be downloaded immediately.
    """

    jobs = [gevent.spawn(send, r) for r in requests]
    gevent.joinall(jobs)

    if prefetch:
        [r.response.content for r in requests]

    return [r.response for r in requests]




