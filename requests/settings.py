# -*- coding: utf-8 -*-

"""
requests.settings
~~~~~~~~~~~~~~~~~

This module provides the Requests settings feature set.

"""

# Time (in seconds) to allow the request to connect to
# the remote host before timing it out.
timeout = None

class Settings(object):

    def __init__(self, **settings):
        self._cache_settings(**settings)
        self._alter_settings(**settings)

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        self._restore_settings()

    def _cache_settings(self, **settings):
        self.cache = {}
        for setting in settings:
            self.cache[setting] = globals()[setting]

    def _alter_settings(self, **settings):
        for setting, value in settings.items():
            globals()[setting] = value

    def _restore_settings(self):
        for setting, value in self.cache.items():
            globals()[setting] = value
