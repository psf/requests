#!/usr/bin/python

import threading, socket

class Server(threading.Thread):
    """ Dummy server using for unit testing """

    def __init__(self, handler, host='localhost', port=0):
        threading.Thread.__init__(self)
        self.handler = handler
        self.host = host
        self.port = port
        self.ready_event = threading.Event()
        self.stop_event = threading.Event()

    @classmethod
    def basic_response_server(cls, host='localhost', port=0):
        def basic_response_handler(server_sock):
            sock, _ = server_sock.accept()
            sock.send(
                b'HTTP/1.1 200 OK\r\n'
                b'Content-Length: 0\r\n'
                b'\r\n'
            )

        server = Server(basic_response_handler, host=host, port=port)
        return server

    def run(self):
        try:
            sock = self._create_socket_and_bind()
            # in case self.port = 0
            self.port = sock.getsockname()[1]
            self.ready_event.set()
            self.handler(sock)
            
        finally:
            self.ready_event.set() # just in case of exception
            sock.close()
            self.stop_event.set()

    def _create_socket_and_bind(self):
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen(0)
        return sock

    def __enter__(self):
       self.start()
       self.ready_event.wait()
       return self.host, self.port
      
    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.stop_event.wait()
        return False # allow exceptions to propagate 
    
