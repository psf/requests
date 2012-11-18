# mycache = ReqCache("test", "memory")
import requests
s = requests.session()

r = s.get('http://github.com')
print r.__dict__.get('from_cache')

r = s.get('http://github.com')
print r.__dict__.get('from_cache')


r = s.get('http://github.com')
print r.__dict__.get('from_cache')

r = s.get('http://github.com')
print r.__dict__.get('from_cache')

r = s.get('http://github.com')
print r.__dict__.get('from_cache')

r = s.get('http://github.com')
print r.__dict__.get('from_cache')
# r = requests.get('http://github.com', hooks=mycache.hooks)

# r = requests.get('http://github.com', hooks=mycache.hooks)
# explain_cache_result(r)
