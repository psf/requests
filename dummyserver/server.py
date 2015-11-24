#!/usr/bin/python

import threading, socket



"""
Dummy server using for unit testing
"""

class Server(threading.Thread):
    def __init__(self, handler, host='localhost', port=8021):
        threading.Thread.__init__(self)
        self.handler = handler
        self.host = host
        self.port = port
        self.ready_event = threading.Event()
        self.stop_event = threading.Event()

    def run(self):
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen(0)
        self.ready_event.set()
        self.handler(sock)
        self.stop_event.set()
        sock.close()

    def __enter__(self):
       self.start()
       self.ready_event.wait()
       return self.host, self.port
      
    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.stop_event.wait()
        return False # allow exceptions to propagate 
    
