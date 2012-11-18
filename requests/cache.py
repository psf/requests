#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
requests.cache
~~~~~~~~~~~~~~

Requests caching layer.
"""

import time
import hashlib
import calendar
import email
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




class Cache(object):
    """A Cache session."""
    def __init__(self, backend=None, conditional=None, content=True, handler=None):

        self.conditional = None
        self.content = None
        self.handler = handler

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

        if handler is None:
            self.handler = CacheHandler()



class CacheHandler(object):


    @staticmethod
    def request_hash(r, type=''):
        """Returns a SHA256(type-method-url) for cache keys."""

        s = '{0}-{1}-{2}'.format(type, r.request.method, r.request.full_url)
        return hashlib.sha256(s).hexdigest()


    @staticmethod
    def _parse_cache_control(headers):
        """
        Parse the cache control headers returning a dictionary with values
        for the different directives.
        """
        retval = {}
        if 'cache-control' in headers:
            parts = headers['cache-control'].split(',')
            parts_with_args = [
                tuple([x.strip().lower() for x in part.split("=", 1)])
                for part in parts if -1 != part.find("=")]
            parts_wo_args = [(name.strip().lower(), 1)
                             for name in parts if -1 == name.find("=")]
            retval = dict(parts_with_args + parts_wo_args)
        return retval

    def cache_request(self, r, cache):
        """See if we should use a cached response."""

        return True
        cache_hash = self.request_hash(r)
        cc = self._parse_cache_control(r.headers)

        # non-caching states
        no_cache = False
        if 'no-cache' in cc:
            no_cache = True
        if 'max-age' in cc and cc['max-age'] == 0:
            no_cache = True

        # see if it is in the cache anyways
        in_cache = cache.get(cache_hash)
        if no_cache or not in_cache:
            return False

        # It is in the cache, so lets see if it is going to be
        # fresh enough
        resp = cache.get(cache_hash)
        now = time.time()
        date = calendar.timegm(
            email.Utils.parsedate_tz(resp.headers['date']))
        current_age = max(0, now - date)

        resp_cc = self._parse_cache_control(resp.headers)


        # determine freshness
        freshness_lifetime = 0
        if 'max-age' in resp_cc:
            try:
                freshness_lifetime = int(resp_cc['max-age'])
            except ValueError:
                pass
        elif 'expires' in resp.headers:
            expires = email.Utils.parsedate_tz(resp.headers['expires'])
            if expires != None:
                expire_time = calendar.timegm(expires) - date
                freshness_lifetime = max(0, expire_time)

        # determine if we are setting freshness limit in the req
        if 'max-age' in cc:
            try:
                freshness_lifetime = int(cc['max-age'])
            except ValueError:
                freshness_lifetime = 0

        if 'min-fresh' in cc:
            try:
                min_fresh = int(cc['min-fresh'])
            except ValueError:
                min_fresh = 0
            # adjust our current age by our min fresh
            current_age += min_fresh

        # see how fresh we actually are
        fresh = (freshness_lifetime > current_age)

        if fresh:
            # make sure we set the from_cache to true
            resp.from_cache = True
            return resp

        # we're not fresh, clean out the junk
        cache.delete(cache_hash)

        # return the original handler
        return False


    def cache_response(self, r, cache):
        """Algorithm for caching requests."""

        if r.status_code not in [200, 203]:
            return

        cc_req = self._parse_cache_control(r.request.headers)
        cc = self._parse_cache_control(r.headers)

        # cache_url = self.cache_url(r.request.full_url)
        cache_hash = self.request_hash(r)

        # Delete it from the cache if we happen to have it stored there
        no_store = cc.get('no-store') or cc_req.get('no-store')
        if no_store and cache.get(cache_hash):
            cache.delete(cache_hash)

        # Add to the cache if the response headers demand it. If there
        # is no date header then we can't do anything about expiring
        # the cache.
        if 'date' in r.headers:

            # cache when there is a max-age > 0
            if cc and cc.get('max-age'):
                if int(cc['max-age']) > 0:
                    cache.set(cache_hash, r)

            # If the request can expire, it means we should cache it
            # in the meantime.
            elif 'expires' in r.headers:
                if int(r.headers['expires']) > 0:
                    cache.set(cache_hash, r)
