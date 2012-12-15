import requests
import unittest


class IterationTestCase(unittest.TestCase):

    def test_assertion(self):
        assert 1

    # def test_dzubia(self):
    #     s = requests.Session()
    #     r = requests.Request(method='GET', url='http://github.com/')

    #     # r = s.send(r)

    def test_prepared_request(self):
        s = requests.Session()
        r = requests.Request(method='GET', url='http://github.com/')
        r = r.prepare()

        r = s.send(r)
        print r





if __name__ == '__main__':
    unittest.main()