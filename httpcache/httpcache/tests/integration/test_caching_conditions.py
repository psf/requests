from httpcache import CacheControl
import requests


class TestCachingConditions(object):

    def test_no_caching_directives(self):
        url = 'http://localhost:8080/'
        s = requests.Session()
        c = CacheControl(s, {})
        r = c.get(url)

        assert r
        assert r.content == 'foo'
        assert not c.cache.get(url)

    def test_cache_max_age(self):
        url = 'http://localhost:8080/max_age/'
        s = requests.Session()
        c = CacheControl(s, {})
        r = c.get(url)
        assert c.cache.get(url)
        assert c.cache.get(url) == r

    def test_cache_no_cache(self):
        url = 'http://localhost:8080/no_cache/'
        s = requests.Session()
        c = CacheControl(s, {})
        c.get(url)
        assert not c.cache.get(url)

    def test_cache_must_revalidate(self):
        url = 'http://localhost:8080/must_revalidate/'
        s = requests.Session()
        c = CacheControl(s, {})
        c.get(url)
        assert not c.cache.get(url)

    def test_cache_no_store(self):
        url = 'http://localhost:8080/no_store/'
        s = requests.Session()
        c = CacheControl(s, {})
        c.get(url)
        assert not c.cache.get(url)
