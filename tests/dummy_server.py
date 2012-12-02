import asyncore
import threading
import socket

class HttpServer(threading.Thread):
    def __init__(self, port):
        threading.Thread.__init__(self)
        self.dispatcher = HttpServerDispatcher(port)

    def run(self):
        asyncore.loop()

    @property
    def connection_count(self):
        return self.dispatcher.connection_count

    def close(self):
        asyncore.close_all()

class HttpServerDispatcher(asyncore.dispatcher):
    def __init__(self, port):
        asyncore.dispatcher.__init__(self)
        self.connected = False
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind(('127.0.0.1', port))
        self.listen(1)
        self.connection_count = 0

    def handle_accept(self):
        self.connection_count += 1
        self.handler = RequestHandler(self.accept()[0])

    def handle_close(self):
        self.close()


class RequestHandler(asyncore.dispatcher_with_send):
    def __init__(self, sock):
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.response = ("HTTP/1.1 200 OK\r\n"
                         "Connection: keep-alive\r\n"
                         "Content-Length: 0\r\n\r\n")

    def handle_read(self):
        self.recv(1024)
        self.send(self.response)
