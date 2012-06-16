import requests
from furl import furl


def test_url():
    print requests.get(furl('http://www.google.com/?one=1&two=2'))
    print requests.get(furl('http://example.com/ ').set({'query':'string'}))
    print requests.get(furl('http://www.google.com/?one=1'))

test_url()
