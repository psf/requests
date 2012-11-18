"""
A caching wrapper for the requests session.
"""
import re
import email
import calendar
import time

import requests
from cache import DictCache


URI = re.compile(r"^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?")


def parse_uri(uri):
    """Parses a URI using the regex given in Appendix B of RFC 3986.

        (scheme, authority, path, query, fragment) = parse_uri(uri)
    """
    groups = URI.match(uri).groups()
    return (groups[1], groups[3], groups[4], groups[6], groups[8])


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


def urlnorm(uri):
    (scheme, authority, path, query, fragment) = parse_uri(uri)
    if not scheme or not authority:
        raise Exception("Only absolute URIs are allowed. uri = %s" % uri)
    authority = authority.lower()
    scheme = scheme.lower()
    if not path:
        path = "/"
    # Could do syntax based normalization of the URI before
    # computing the digest. See Section 6.2.2 of Std 66.
    request_uri = query and "?".join([path, query]) or path
    scheme = scheme.lower()
    defrag_uri = scheme + "://" + authority + request_uri
    return scheme, authority, request_uri, defrag_uri


class CacheControl(object):

    def __init__(self, session, cache=None):
        self.session = session
        self.cache = cache or DictCache()

    def __getattr__(self, key):
        if hasattr(self.session, key):
            return getattr(self.session, key)
        raise AttributeError('%s not found' % key)

    def cache_url(self, url):
        scheme, authority, request_uri, defrag_uri = urlnorm(url)
        return defrag_uri

    def cached_request(self, *args, **kw):
        """
        See if we should use a cached response. We are looking for
        client conditions such as no-cache and testing our cached
        value to see if we should use it or not.

        This is taken almost directly from httplib2._entry_disposition
        """
        req = requests.Request(*args, **kw)
        cache_url = self.cache_url(req.full_url)

        cc = _parse_cache_control(req.headers)

        # non-caching states
        no_cache = False
        if 'no-cache' in cc: no_cache = True
        if 'max-age' in cc and cc['max-age'] == 0: no_cache = True

        # see if it is in the cache anyways
        in_cache = self.cache.get(cache_url)
        if no_cache or not in_cache:
            return False

        # It is in the cache, so lets see if it is going to be
        # fresh enough
        resp = self.cache.get(cache_url)
        now = time.time()
        date = calendar.timegm(
            email.Utils.parsedate_tz(resp.headers['date']))
        current_age = max(0, now - date)

        resp_cc = _parse_cache_control(resp.headers)

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
        self.cache.delete(cache_url)

        # return the original handler
        return False

    def cache_response(self, resp):
        """
        Algorithm for caching requests
        """

        # From httplib2: Don't cache 206's since we aren't going to
        # handle byte range requests
        if resp.status_code not in [200, 203]:
            return

        cc_req = _parse_cache_control(resp.request.headers)
        cc = _parse_cache_control(resp.headers)

        cache_url = self.cache_url(resp.request.full_url)

        # Delete it from the cache if we happen to have it stored there
        no_store = cc.get('no-store') or cc_req.get('no-store')
        if no_store and self.cache.get(cache_url):
            self.cache.delete(cache_url)

        # Add to the cache if the response headers demand it. If there
        # is no date header then we can't do anything about expiring
        # the cache.
        if 'date' in resp.headers:

            # cache when there is a max-age > 0
            if cc and cc.get('max-age'):
                if int(cc['max-age']) > 0:
                    self.cache.set(cache_url, resp)

            # If the request can expire, it means we should cache it
            # in the meantime.
            elif 'expires' in resp.headers:
                if int(resp.headers['expires']) > 0:
                    self.cache.set(cache_url, resp)

    def from_cache(f):
        """
        A decorator that allows using a cached response.
        """
        def cached_handler(self, *args, **kw):
            # If we have a cached response use it
            cached_response = self.cached_request(*args, **kw)
            if cached_response:
                return cached_response

            # Else return original function's response
            return f(self, *args, **kw)
        return cached_handler

    def invalidates_cache(f):
        """
        A decorator for marking methods that can invalidate the cache.
        """

        def invalidating_handler(self, *args, **kw):
            resp = f(self, *args, **kw)
            if resp.ok:
                cache_url = self.cache_url(resp.request.full_url)
                self.cache.delete(cache_url)
            return resp
        return invalidating_handler

    @from_cache
    def get(self, url, headers=None, *args, **kw):
        resp = self.session.get(url, headers=headers, *args, **kw)
        # We set this primarily for testing
        resp.from_cache = False

        # See if we need to cache the response
        self.cache_response(resp)

        # actually return the repsonse
        return resp

    @invalidates_cache
    def put(self, *args, **kw):
        return self.session.put(*args, **kw)

    @invalidates_cache
    def delete(self, *args, **kw):
        return self.session.delete(*args, **kw)
