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
    from gevent.pool import Pool
except ImportError:
    raise RuntimeError('Gevent is required for requests.async.')

# Monkey-patch.
curious_george.patch_all(thread=False)

from . import api


__all__ = (
    'map',
    'get', 'options', 'head', 'post', 'put', 'patch', 'delete', 'request'
)


def patched(f):
    """Patches a given API function to not send."""

    def wrapped(*args, **kwargs):

        kwargs['return_response'] = False
        kwargs['prefetch'] = True

        config = kwargs.get('config', {})
        config.update(safe_mode=True)

        kwargs['config'] = config

        return f(*args, **kwargs)

    return wrapped


def send(r, pool=None):
    """Sends the request object using the specified pool. If a pool isn't 
    specified this method blocks. Pools are useful because you can specify size
    and can hence limit concurrency."""

    if pool != None:
        return pool.spawn(r.send)

    return gevent.spawn(r.send)


# Patched requests.api functions.
get = patched(api.get)
options = patched(api.options)
head = patched(api.head)
post = patched(api.post)
put = patched(api.put)
patch = patched(api.patch)
delete = patched(api.delete)
request = patched(api.request)


def map(requests, prefetch=True, size=None):
    """Concurrently converts a list of Requests to Responses.

    :param requests: a collection of Request objects.
    :param prefetch: If False, the content will not be downloaded immediately.
    :param size: Specifies the number of requests to make at a time. If None, no throttling occurs.
    """

    requests = list(requests)

    pool = Pool(size) if size else None
    jobs = [send(r, pool) for r in requests]
    gevent.joinall(jobs)

    if prefetch:
        [r.response.content for r in requests]

    return [r.response for r in requests]