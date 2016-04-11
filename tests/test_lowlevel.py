import threading
import requests

from tests.testserver.server import Server


def test_chunked_upload():
    """can safely send generators"""
    close_server = threading.Event()
    server = Server.basic_response_server(wait_to_close_event=close_server)
    data = (i for i in [b'a', b'b', b'c']) 

    with server as (host, port):
        url = 'http://{0}:{1}/'.format(host, port)
        r = requests.post(url, data=data, stream=True)
        close_server.set() # release server block

    assert r.status_code == 200
    assert r.request.headers['Transfer-Encoding'] == 'chunked'
