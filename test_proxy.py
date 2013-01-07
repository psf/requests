import os
import urlparse

import mox
import unittest
from requests import utils

"""
def main():
    url = 'http://orion.spf.cl.nec.co.jp/'
    print url
    print utils.get_environ_proxies(url)

    url = 'http://127.0.0.1/'
    print url
    print utils.get_environ_proxies(url)

    url = 'http://10.56.133.25/'
    print url
    print utils.get_environ_proxies(url)
"""

class RequestsProxyTest(unittest.TestCase):
    def setUp(self):
        self.mox = mox.Mox()
        self.mox.StubOutWithMock(os.environ, "get")

    def tearDown(self):
        self.mox.UnsetStubs()

    def test_no_proxy_domain(self):
        url = 'http://httpbin.org/get'
        host = urlparse.urlparse(url).netloc
        os.environ.get('no_proxy').AndReturn('.org,10.56.1.0/24')
        self.mox.ReplayAll()
        proxies = utils.get_environ_proxies(url)
        self.assertEqual(proxies, {})
        self.mox.VerifyAll()

    def test_no_proxy_network(self):
        url = 'http://10.56.1.1/get'
        host = urlparse.urlparse(url).netloc
        os.environ.get('no_proxy').AndReturn('.org,10.56.1.0/24')
        self.mox.ReplayAll()
        proxies = utils.get_environ_proxies(url)
        self.assertEqual(proxies, {})
        self.mox.VerifyAll()

if __name__ == '__main__':
    unittest.main()
