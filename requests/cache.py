#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
requests.cache
~~~~~~~~~~~~~~

Requests caching layer.
"""

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



