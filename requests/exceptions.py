# -*- coding: utf-8 -*-

"""
requests.exceptions
~~~~~~~~~~~~~~~~~~~

This module contains the set of Requests' exceptions.

"""

class RequestException(Exception):
    """There was an ambiguous exception that occurred while handling your
    request."""

class HTTPError(RequestException):
    """An HTTP error occured."""

class ConnectionError(RequestException):
    """A Connection error occured."""

class Timeout(RequestException):
    """The request timed out."""

class URLRequired(RequestException):
    """A valid URL is required to make a request."""

class TooManyRedirects(RequestException):
    """Too many redirects."""
