#-*- coding: utf-8 -*-

"""
requests.monkeys
~~~~~~~~~~~~~~~~

Urllib2 Monkey patches.

"""

import urllib2
import httplib
import socket
import sys
import re

try:
    import ssl
    have_ssl = True
except ImportError:
    have_ssl = False
    
class Request(urllib2.Request):
    """Hidden wrapper around the urllib2.Request object. Allows for manual
    setting of HTTP methods.
    """

    def __init__(self, url, data=None, headers={}, origin_req_host=None, unverifiable=False, method=None):
        urllib2.Request.__init__(self, url, data, headers, origin_req_host, unverifiable)
        self.method = method

    def get_method(self):
        if self.method:
            return self.method

        return urllib2.Request.get_method(self)


class HTTPRedirectHandler(urllib2.HTTPRedirectHandler):
    """HTTP Redirect handler."""
    def _pass(self, req, fp, code, msg, headers):
        pass

    http_error_302 = _pass
    http_error_303 = _pass
    http_error_307 = _pass
    http_error_301 = _pass


def create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None):
    """Connect to *address* and return the socket object.

    Convenience function.  Connect to *address* (a 2-tuple ``(host,
    port)``) and return the socket object.  Passing the optional
    *timeout* parameter will set the timeout on the socket instance
    before attempting to connect.  If no *timeout* is supplied, the
    global default timeout setting returned by :func:`getdefaulttimeout`
    is used.  If *source_address* is set it must be a tuple of (host, port)
    for the socket to bind as a source address before making the connection.
    An host of '' or port 0 tells the OS to use the default.
    """

    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock

        except socket.error as _:
            err = _
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    else:
        raise socket.error("getaddrinfo returns an empty list")


def build_bindable_http_handler(source_address, https=False):
    if https and not have_ssl:
        raise RuntimeError("SSL library not found.")
        
    def bindable_http_connection_factory(source_address):        
        class HTTPConnection(httplib.HTTPConnection):
            def __init__(self, *args, **kwargs):
                self.source_address = kwargs.pop('source_address', None)
                httplib.HTTPConnection.__init__(self, *args, **kwargs)
                
            def connect(self):
                self.sock = create_connection(
                    (self.host, self.port),
                    self.timeout, self.source_address)

                if self._tunnel_host:
                    self._tunnel()

        class HTTPSConnection(httplib.HTTPSConnection):
            def __init__(self, *args, **kwargs):
                self.source_address = kwargs.pop('source_address', None)
                httplib.HTTPConnection.__init__(self, *args, **kwargs)
                
            def connect(self):
                self.sock = create_connection(
                    (self.host, self.port),
                    self.timeout, self.source_address)

                if self._tunnel_host:
                    self._tunnel()
                self.sock = ssl.wrap_socket(self.sock, self.key_file, self.cert_file)
                    
        def _get(*args, **kwargs):
            kwargs['source_address'] = source_address
            if sys.version_info <= (2, 7):
                if https:
                    return HTTPSConnection(*args, **kwargs)
                return HTTPConnection(*args, **kwargs)
            if https:
                return httplib.HTTPSConnection(*args, **kwargs)
            return httplib.HTTPConnection(*args, **kwargs)
        
        return _get

    class HTTPHandler(urllib2.HTTPHandler):
        def http_open(self, req):
            return self.do_open(
                bindable_http_connection_factory(source_address), req
            )
    
        http_request = urllib2.AbstractHTTPHandler.do_request_

    class HTTPSHandler(urllib2.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(
                bindable_http_connection_factory(source_address), req
            )
    
        http_request = urllib2.AbstractHTTPHandler.do_request_
        
    return HTTPSHandler if https else HTTPHandler
