===========
 httpcache
===========

Httpcache is a port of the caching algorithms in httplib2_ for use with
requests_ session object. 

It was written because httplib2's better support for caching is often
mitigated by its lack of threadsafety. The same is true of requests in
terms of caching.


Usage
=====

NOTE: Eventually, my hope is that this module can be integrated directly
into requests. That said, I've had minimal exposure to requests, so I
expect the initial implementation to be rather un-requests-like in
terms of its API. Suggestions and patches welcome!

Here is the basic usage: ::

  import requests

  from httpcache import CacheControl


  sess = requests.session()
  cached_sess = CacheControl(sess)

  response = cached_sess.get('http://google.com')

If the URL contains any caching based headers, it will cache the
result in a simple dictionary. 

Below is the implementation of the DictCache, the default cache
backend. It is extremely simple and shows how you would implement some
other cache backend: ::

  from httpcache.cache import BaseCache


  class DictCache(BaseCache):
   
      def __init__(self, init_dict=None):
          self.data = init_dict or {}
   
      def get(self, key):
          return self.data.get(key, None)
   
      def set(self, key, value):
          self.data.update({key: value})
   
      def delete(self, key):
          self.data.pop(key)

  

See? Really simple.


Design
======

The CacheControl object's main task is to wrap the GET call of the
session object. The caching takes place by examining the request to
see if it should try to ue the cache. For example, if the request
includes a 'no-cache' or 'max-age=0' Cache-Control header, it will not
try to cache the request. If there is an cached value and its value
has been deemed fresh, the it will return the cached response.

If the request cannot be cached, the actual request is peformed. At
this point we then analyze the response and see if we should add it to
the cache. For example, if the request contains a 'max-age=3600' in
the 'Cache-Control' header, it will cache the response before
returning it to the caller. 


Tests
=====

The tests are all in httpcache/tests and is runnable by py.test. 


TODO
====

 [ ]- Better integration with requests
 [ ]- ETags / if-* header support
 [ ]- Tests that run a server from the stdlib


Disclaimers
===========

Httpcache is brand new and maybe totally broken. I have some tests and
it is a pretty direct port of httplib2 caching, which I've found to be
very reliable. With that in mind, it hasn't been used in a production
environment just yet. If you check it out and find bugs, let me know.


.. _httplib2: http://code.google.com/p/httplib2/
.. _requests: http://docs.python-requests.org/ 
