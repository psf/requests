import os
import py.test
import subprocess
import requests
import time


class TestServer(object):

    def start(self):
        base = os.path.abspath(os.path.dirname(__file__))
        server_file = os.path.join(base, 'httpcache', 'tests', 'server.py')
        cmd = ['python', server_file]

        kw = {}
        if not os.environ.get('TEST_SERVER_OUTPUT'):
            kw = {'stdout': subprocess.PIPE,
                  'stderr': subprocess.STDOUT}
        self.proc = subprocess.Popen(cmd, **kw)
        url = 'http://localhost:8080'
        up = None
        while not up:
            try:
                up = requests.get(url)
            except requests.ConnectionError:
                time.sleep(1)

    def stop(self):
        self.proc.terminate()


def pytest_namespace():
    return dict(server=TestServer())


def pytest_configure(config):
    py.test.server.start()


def pytest_unconfigure(config):
    py.test.server.stop()
