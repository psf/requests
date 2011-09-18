# -*- coding: utf-8 -*-

"""
requests.exceptions
~~~~~~~~~~~~~~~

"""

class RequestException(Exception):
    """There was an ambiguous exception that occured while handling your
    request."""

class Timeout(RequestException):
    """The request timed out."""

class URLRequired(RequestException):
    """A valid URL is required to make a request."""

class TooManyRedirects(RequestException):
    """Too many redirects."""
