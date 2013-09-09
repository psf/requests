# -*- coding: utf-8 -*-

"""
requests.exceptions
~~~~~~~~~~~~~~~~~~~

This module contains the set of Requests' exceptions.

"""


class RequestException(RuntimeError):
    """There was an ambiguous exception that occurred while handling your
    request."""


class HTTPError(RequestException):
    """An HTTP error occurred."""

    def __init__(self, *args, **kwargs):
        """ Initializes HTTPError with optional `response` object. """
        self.response = kwargs.pop('response', None)
        super(HTTPError, self).__init__(*args, **kwargs)


class ConnectionError(RequestException):
    """A Connection error occurred."""
    def __init__(self, wrapped_exception):
        strerror, errno = get_strerror_and_errno(wrapped_exception)
        super(ConnectionError, self).__init__(strerror)
        self.strerror, self.errno = strerror, errno


class SSLError(ConnectionError):
    """An SSL error occurred."""


class Timeout(RequestException):
    """The request timed out."""
    def __init__(self, strerror, errno):
        super(Timeout, self).__init__(strerror)
        self.strerror, self.errno = strerror, errno


class URLRequired(RequestException):
    """A valid URL is required to make a request."""


class TooManyRedirects(RequestException):
    """Too many redirects."""


class MissingSchema(RequestException, ValueError):
    """The URL scheme (e.g. http or https) is missing."""


class MissingScheme(MissingSchema):
    """The URL scheme (e.g. http or https) is missing."""


class InvalidSchema(RequestException, ValueError):
    """See defaults.py for valid schemes."""


class InvalidScheme(InvalidSchema):
    """See defaults.py for valid schemes."""


class InvalidURL(RequestException, ValueError):
    """ The URL provided was somehow invalid. """


class ChunkedEncodingError(RequestException):
    """The server declared chunked encoding but sent an invalid chunk."""
