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

    def run(self):
        try:
            sock = self._create_socket_and_bind()
            # in case self.port = 0
            self.port = sock.getsockname()[1]
            self.ready_event.set()
            self.handler(sock)
            
        finally:
            self.ready_event.set() # just in case of exception
            self.stop_event.set()
            sock.close()

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
    
