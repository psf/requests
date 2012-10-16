"""
When resources are known to be updated via HTTP (ie PUT, DELETE), we
should invalidate them in our cache.
"""
import mock

from httpcache import CacheControl
from httpcache.cache import DictCache


class TestInvalidations(object):

    url = 'http://foo.com/bar/'

    def resp(self):
        req = mock.Mock(full_url=self.url)
        return mock.Mock(request=req)

    def test_put_invalidates_cache(self):
        # Prep our cache
        resp = self.resp()
        cache = DictCache({self.url: resp})
        session = mock.Mock(put=mock.Mock(return_value=resp))
        c = CacheControl(session, cache)

        c.put(self.url)

        assert not c.cache.get(self.url)

    def test_delete_invalidates_cache(self):
        # Prep our cache
        resp = self.resp()
        cache = DictCache({self.url: resp})
        session = mock.Mock(delete=mock.Mock(return_value=resp))
        c = CacheControl(session, cache)

        c.delete(self.url)

        assert not c.cache.get(self.url)
