from __future__ import print_function
from .. import CacheControl
import requests


class TestMaxAge(object):

    def test_client_max_age_0(self):
        """
        Making sure when the client uses max-age=0 we don't get a
        cached copy even though we're still fresh.
        """
        url = 'http://localhost:8080/max_age/'
        s = requests.Session()
        c = CacheControl(s, {})
        print('first request')
        r = c.get(url)
        cache_url = c.cache_url(url)
        assert c.cache.get(cache_url) == r

        print('second request')
        r = c.get(url, headers={'Cache-Control': 'max-age=0'})

        # don't remove from the cache
        assert c.cache.get(cache_url)
        assert r.from_cache == False

    def test_client_max_age_3600(self):
        """
        Verify we get a cached value when the client has a
        reasonable max-age value.
        """
        # prep our cache
        url = 'http://localhost:8080/max_age/'
        s = requests.Session()
        c = CacheControl(s, {})
        r = c.get(url)
        cache_url = c.cache_url(url)
        assert c.cache.get(cache_url) == r

        # request that we don't want a new one unless
        r = c.get(url, headers={'Cache-Control': 'max-age=3600'})
        assert r.from_cache == True

        # now lets grab one that forces a new request b/c the cache
        # has expired. To do that we'll inject a new time value.
        resp = c.cache.get(cache_url)
        resp.headers['date'] = 'Tue, 15 Nov 1994 08:12:31 GMT'
        r = c.get(url)
        assert r.from_cache == False
