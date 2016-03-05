import threading
import socket
import time

import pytest
import requests
from testserver.server import Server

class TestTestServer:
    def test_basic(self):
        question = b"sucess?"
        answer = b"yeah, success"
        def handler(sock):
            text = sock.recv(1000)
            assert text == question 
            sock.sendall(answer)
        
        with Server(handler) as (host, port):
            sock = socket.socket()
            sock.connect((host, port))
            sock.sendall(question)
            text = sock.recv(1000)
            assert text == answer
            sock.close()

    def test_server_closes(self):
        with Server.basic_response_server() as (host, port):
            sock = socket.socket()
            sock.connect((host, port))

            sock.close()

        with pytest.raises(socket.error):
            new_sock = socket.socket()
            new_sock.connect((host, port))

    def test_text_response(self):
        server = Server.text_response_server(
            "HTTP/1.1 200 OK\r\n" + 
            "Content-Length: 6\r\n" +
            "\r\nroflol"
        )

        with server as (host, port):
            r = requests.get('http://{0}:{1}'.format(host, port))

            assert r.status_code == 200
            assert r.text == 'roflol'
            assert r.headers['Content-Length'] == '6' 
            
    def test_basic_response(self):
        with Server.basic_response_server() as (host, port):
            r = requests.get('http://{0}:{1}'.format(host, port))
            assert r.status_code == 200
            assert r.text == ''
            assert r.headers['Content-Length'] == '0'

    def test_basic_waiting_server(self):
        block_server = threading.Event()

        with Server.basic_response_server(wait_to_close_event=block_server) as (host, port):
            sock = socket.socket()
            sock.connect((host, port))
            sock.sendall(b'send something')
            time.sleep(2.5)
            sock.sendall(b'still alive')
            block_server.set() # release server block

    def test_multiple_requests(self):
        requests_to_handle = 5
        
        server = Server.basic_response_server(requests_to_handle=requests_to_handle)

        with server as (host, port):
            server_url = 'http://{0}:{1}'.format(host, port)
            for _ in range(requests_to_handle):
                r = requests.get(server_url)
                assert r.status_code == 200

            # the (n+1)th request fails
            with pytest.raises(requests.exceptions.ConnectionError):
                r = requests.get(server_url)

    def test_request_recovery(self):
        server = Server.basic_response_server(requests_to_handle=2)
        first_request = "put your hands up in the air"
        second_request = "put your hand down in the floor"

        with server as address:
            sock1 = socket.socket()
            sock2 = socket.socket()
            
            sock1.connect(address)
            sock1.sendall(first_request.encode())
            sock1.close()

            sock2.connect(address)
            sock2.sendall(second_request.encode())
            sock2.close()

        assert server.handler_results[0] == first_request
        assert server.handler_results[1] == second_request

    def test_requests_after_timeout_are_not_received(self):
        server = Server.basic_response_server(request_timeout=1)

        with server as address:
            sock = socket.socket()
            sock.connect(address)
            time.sleep(1.5)
            sock.sendall(b"hehehe, not received")
            sock.close()

        assert server.handler_results[0] == ""


    def test_request_recovery_with_bigger_timeout(self):
        server = Server.basic_response_server(request_timeout=3)
        data = "bananadine"

        with server as address:
            sock = socket.socket() 
            sock.connect(address)
            time.sleep(1.5)
            sock.sendall(data.encode())
            sock.close()
            
        assert server.handler_results[0] == data
