#!/usr/bin/python

import threading 
import socket
import select


def consume_socket_content(sock, chunks=65536, timeout=0.5):
    content = ""
    more_to_read = select.select([sock], [], [], timeout)[0]

    while more_to_read:
        new_content = sock.recv(chunks).decode("utf-8")

        if len(new_content) == 0:
            more_to_read = False # empty recv means the socket disconnected

        else:
            content += new_content 
            # stop reading if no new data is received for a while 
            more_to_read = select.select([sock], [], [], timeout)[0] 

    return content

class Server(threading.Thread):
    """ Dummy server using for unit testing """

    def __init__(self, handler, host='localhost', port=0, requests_to_handle=1, wait_to_close_event=None):
        threading.Thread.__init__(self)

        self.handler = handler
        self.handler_results = []

        self.host = host
        self.port = port
        self.requests_to_handle = requests_to_handle
 
        self.wait_to_close_event = wait_to_close_event
        self.ready_event = threading.Event()
        self.stop_event = threading.Event()

    @classmethod
    def text_response_server(cls, text, request_timeout=0.5, **kwargs):
        def text_response_handler(sock):
            request_content = consume_socket_content(sock, timeout=request_timeout)
            sock.send(text.encode())

            return request_content


        server = Server(text_response_handler, **kwargs)

        return server

    @classmethod
    def basic_response_server(cls, **kwargs):
        server = cls.text_response_server(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Length: 0\r\n\r\n", **kwargs
        )

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
            handler_result = self.handler(sock)

            self.handler_results.append(handler_result)
        
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
    
