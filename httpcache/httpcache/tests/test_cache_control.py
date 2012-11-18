"""
Unit tests that verify our caching methods work correctly.
"""
import mock
import datetime
import time

from httpcache import CacheControl
from httpcache.cache import DictCache


TIME_FMT = "%a, %d %b %Y %H:%M:%S"


class TestCacheControlResponse(object):
    url = 'http://url.com/'

    def req(self, headers=None):
        headers = headers or {}
        return mock.Mock(full_url=self.url, headers=headers)

    def resp(self, headers=None):
        headers = headers or {}
        return mock.Mock(status_code=200,
                         headers=headers,
                         request=self.req())

    def cache(self):
        return CacheControl(mock.Mock(), mock.MagicMock())

    def test_no_cache_non_20x_response(self):
        c = self.cache()

        # No caching without some extra headers, so we add them
        now = datetime.datetime.utcnow().strftime(TIME_FMT)
        resp = self.resp({'cache-control': 'max-age=3600',
                          'date': now})

        no_cache_codes = [201, 300, 400, 500]
        for code in no_cache_codes:
            resp.status_code = code
            c.cache_response(resp)
            assert not c.cache.set.called

        # this should work b/c the resp is 20x
        resp.status_code = 203
        c.cache_response(resp)
        assert c.cache.set.called

    def test_no_cache_with_no_date(self):
        c = self.cache()

        # No date header which makes our max-age pointless
        resp = self.resp({'cache-control': 'max-age=3600'})
        c.cache_response(resp)

        assert not c.cache.set.called

    def test_cache_response_no_cache_control(self):
        c = self.cache()
        resp = self.resp()
        c.cache_response(resp)

        assert not c.cache.set.called

    def test_cache_response_cache_max_age(self):
        c = self.cache()

        now = datetime.datetime.utcnow().strftime(TIME_FMT)
        resp = self.resp({'cache-control': 'max-age=3600',
                          'date': now})
        c.cache_response(resp)
        c.cache.set.assert_called_with(self.url, resp)

    def test_cache_repsonse_no_store(self):
        resp = mock.Mock()
        cache = DictCache({self.url: resp})
        c = CacheControl(resp, cache)

        cache_url = c.cache_url(self.url)

        resp = self.resp({'cache-control': 'no-store'})
        assert c.cache.get(cache_url)

        c.cache_response(resp)
        assert not c.cache.get(cache_url)


class TestCacheControlRequest(object):

    url = 'http://foo.com'

    def test_cache_request_no_cache(self):
        c = CacheControl(mock.Mock())
        hdrs = {'cache-control': 'no-cache'}
        resp = c.cached_request(self.url, headers=hdrs)
        assert not resp

    def test_cache_request_pragma_no_cache(self):
        c = CacheControl(mock.Mock())
        hdrs = {'pragma': 'no-cache'}
        resp = c.cached_request(self.url, headers=hdrs)
        assert not resp

    def test_cache_request_no_store(self):
        c = CacheControl(mock.Mock())
        hdrs = {'cache-control': 'no-store'}
        resp = c.cached_request(self.url, headers=hdrs)
        assert not resp

    def test_cache_request_max_age_0(self):
        c = CacheControl(mock.Mock())
        hdrs = {'cache-control': 'max-age=0'}
        resp = c.cached_request(self.url, headers=hdrs)
        assert not resp

    def test_cache_request_not_in_cache(self):
        c = CacheControl(mock.Mock())
        resp = c.cached_request(self.url)
        assert not resp

    def test_cache_request_fresh_max_age(self):
        now = datetime.datetime.utcnow().strftime(TIME_FMT)
        resp = mock.Mock(headers={'cache-control': 'max-age=3600',
                                  'date': now})

        # NOTE: httplib2 uses its own algorithm for finding the
        # "defrag_uri" in order to use it for creating a cache key. It
        # seems to append the trailing slash, which I'm pretty sure is
        # b/c of the auto directory rules. I'm trusting it is correct.
        cache = DictCache({self.url + '/': resp})
        c = CacheControl(mock.Mock(), cache)
        r = c.cached_request(self.url)
        assert r == resp

    def test_cache_request_unfresh_max_age(self):
        earlier = time.time() - 3700
        now = datetime.datetime.fromtimestamp(earlier).strftime(TIME_FMT)

        resp = mock.Mock(headers={'cache-control': 'max-age=3600',
                                  'date': now})
        cache = DictCache({self.url: resp})
        c = CacheControl(mock.Mock(), cache)
        r = c.cached_request(self.url)
        assert not r

    def test_cache_request_fresh_expires(self):
        later = datetime.timedelta(days=1)
        expires = (datetime.datetime.utcnow() + later).strftime(TIME_FMT)
        now = datetime.datetime.utcnow().strftime(TIME_FMT)
        resp = mock.Mock(headers={'expires': expires,
                                  'date': now})
        cache = DictCache({self.url + '/': resp})
        c = CacheControl(mock.Mock, cache)
        r = c.cached_request(self.url)
        assert r == resp

    def test_cache_request_unfresh_expires(self):
        later = datetime.timedelta(days=-1)
        expires = (datetime.datetime.utcnow() + later).strftime(TIME_FMT)
        now = datetime.datetime.utcnow().strftime(TIME_FMT)
        resp = mock.Mock(headers={'expires': expires,
                                  'date': now})
        cache = DictCache({self.url: resp})
        c = CacheControl(mock.Mock, cache)
        r = c.cached_request(self.url)
        assert not r
