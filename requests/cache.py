#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
requests.cache
~~~~~~~~~~~~~~

Requests caching layer.
"""
import hashlib
from .packages.cachecore import SimpleCache

DEFAULT_CACHE = SimpleCache


def expand_cache(c):
    """Expands the default Cache object for Requests.session."""

    if isinstance(c, Cache):
        return c

    if c is True:
        return Cache(backend=DEFAULT_CACHE())

    if c is False:
        return Cache(backend=False)

def request_hash(r, type=''):
    """Returns a SHA256(type-method-url) for cache keys."""

    s = '{0}-{1}-{2}'.format(type, r.request.method, r.request.full_url)

    return hashlib.sha256(s).hexdigest()


class Cache(object):
    """A Cache session."""
    def __init__(self, backend=None, conditional=None, content=True):

        self.conditional = None
        self.content = None

        # Default to backend if True.
        if not backend is None:
            if conditional is True:
                self.conditional = backend

            if content is True:
                self.content = backend

        if conditional is not True:
            self.conditional = conditional

        if content is not True:
            self.content = content

