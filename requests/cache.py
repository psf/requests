# -*- coding: utf-8 -*-
"""
This module contains the primary objects for caching responses
for the Python Requests library.

:copyright: (c) 2012 by Kyle Jensen.
:license: ISC, see LICENSE for more details.
"""
import hashlib
import datetime
import requests
from requests_cache import backends


class ReqCache(object):

    def __init__(self, cache_name, backend,
            allowable_codes=(200,),
            allowable_methods=('GET',),
            expire_after=None,
            **backend_options):

        super(ReqCache, self).__init__()
        self.cache_name = cache_name
        self.backend = backend
        self.allowable_codes = allowable_codes
        self.allowable_methods = allowable_methods
        self.expire_after = expire_after

        try:
            self.cache = backends.registry[self.backend](
                                cache_name,
                                **backend_options
            )
        except KeyError:
            raise ValueError('Unsupported backend "%s" try one of: %s' %
                             (backend, ', '.join(backends.registry.keys())))

    @staticmethod
    def reqresp_to_key(r):
        """
            Accepts a Request or Reponse object, returns a string key for
            storing the cached response in a dictionary-like object.
        """
        if isinstance(r, requests.Response):
            request = r.request
        else:
            request = r

        key = "method={0} url={1}".format(
                request.method,
                request.full_url,
        )

        if request.method in ("POST", "PUT"):
            data = request._encode_params(getattr(r, 'data', {}))
            key = "{0} datahash={2}".format(
                    key,
                    hashlib.sha224(data).hexdigest(),
            )
        return key

    def to_cache(self, response):
        """
            Save a response to the cache.
        """
        if (response.status_code in self.allowable_codes
        and response.request.method in self.allowable_methods
        and not hasattr(response, 'from_cache')):

            key = self.reqresp_to_key(response)
            self.cache.save_response(key, response)

        return response

    def from_cache(self, request):
        """
            Retrieve a response from the cache given a request.
        """
        if request.method in self.allowable_methods:
            key = self.reqresp_to_key(request)
            response, timestamp = self.cache.get_response_and_time(key)

            if response:
                difference = datetime.datetime.now() - timestamp

                if (self.expire_after is not None
                and difference >
                datetime.timedelta(minutes=self.expire_after)):
                    self.cache.del_cached_url(key)
                else:
                    request.sent = True
                    request.response = response
                    request.response.request = request
                    request.response.from_cache = True
        return request

    @property
    def hooks(self):
        return {
            "pre_request": self.from_cache,
            "response": self.to_cache,
        }

if __name__ == '__main__':

    def explain_cache_result(response):
        was_cached = getattr(response, "from_cache", False)
        if was_cached:
            source = "cache"
        else:
            source = "interwebs"

        msg = "Got response from {0} for {1}".format(
                source,
                ReqCache.reqresp_to_key(response.request),
        )
        print msg

    mycache = ReqCache("test", "memory")

    r = requests.get('http://github.com', hooks=mycache.hooks)
    explain_cache_result(r)

    r = requests.get('http://github.com', hooks=mycache.hooks)
    explain_cache_result(r)
