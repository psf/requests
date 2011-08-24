# -*- coding: utf-8 -*-

"""
requests.exceptions
~~~~~~~~~~~~~~~

"""

class RequestException(Exception):
    """There was an ambiguous exception that occured while handling your
    request."""

class AuthenticationError(RequestException):
    """The authentication credentials provided were invalid."""
    
class Timeout(RequestException):
    """The request timed out."""

class URLRequired(RequestException):
    """A valid URL is required to make a request."""

class InvalidMethod(RequestException):
    """An inappropriate method was attempted."""

class TooManyRedirects(RequestException):
    """Too many redirects."""
