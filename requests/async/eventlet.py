# -*- coding: utf-8 -*-

from __future__ import absolute_import

try:
    import eventlet
    from eventlet import patcher as curious_george
except ImportError:
    raise RuntimeError('Eventlet is required for requests.async.')

# Monkey-patch.
curious_george.monkey_patch(thread=False)

from .. import async
from ..async import *
from ..async import _send

__all__ = ('map',) + async.__all__


def map(requests, prefetch=True):
    """Concurrently converts a list of Requests to Responses.

    :param requests: a collection of Request objects.
    :param prefetch: If False, the content will not be downloaded immediately.
    """

    pool = eventlet.GreenPool()
    [pool.spawn(_send, r) for r in requests]
    pool.waitall()

    if prefetch:
        [r.response.content for r in requests]

    return [r.response for r in requests]

