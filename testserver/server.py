#!/usr/bin/python

import threading 
import socket

def consume_socket(sock, chunks=65536):
    while not sock.recv(chunks).endswith(b'\r\n\r\n'):
            pass


class Server(threading.Thread):
    """ Dummy server using for unit testing """

    def __init__(self, handler, host='localhost', port=0, requests_to_handle=1, wait_to_close_event=None):
        threading.Thread.__init__(self)
        self.handler = handler
        self.host = host
        self.port = port
        self.requests_to_handle = requests_to_handle
 
        self.wait_to_close_event = wait_to_close_event
        self.ready_event = threading.Event()
        self.stop_event = threading.Event()

    @classmethod
    def basic_response_server(cls, **kwargs):
        def basic_response_handler(sock):
            sock.send(
                b'HTTP/1.1 200 OK\r\n'
                b'Content-Length: 0\r\n'
                b'\r\n'
            )

        server = Server(basic_response_handler, **kwargs)
        return server


    def run(self):
        try:
            sock = self._create_socket_and_bind()
            # in case self.port = 0
            self.port = sock.getsockname()[1]
            self.ready_event.set()
            self._handle_requests_and_close_server(sock)
        finally:
            self.ready_event.set() # just in case of exception
            sock.close()
            self.stop_event.set()

    def _create_socket_and_bind(self):
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen(0)
        return sock

    def _handle_requests_and_close_server(self, server_sock):
        for _ in range(self.requests_to_handle):
            sock = server_sock.accept()[0]
            self.handler(sock)
        
        if self.wait_to_close_event:
            self.wait_to_close_event.wait()
        
    def __enter__(self):
       self.start()
       self.ready_event.wait()
       return self.host, self.port
      
    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.stop_event.wait()
        else:
            if self.wait_to_close_event:
                # avoid server from blocking if an exception is found
                # in the main thread
                self.wait_to_close_event.set() 
        return False # allow exceptions to propagate 
    
