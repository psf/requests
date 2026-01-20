"""
requests.exceptions
~~~~~~~~~~~~~~~~~~~

This module contains the set of Requests' exceptions.
"""
from urllib3.exceptions import HTTPError as BaseHTTPError

from .compat import JSONDecodeError as CompatJSONDecodeError


class RequestException(IOError):
    """
    There was an ambiguous exception that occurred while handling your
        request.
    """


    def __init__(self, *args, **kwargs):
        """
        Initialize a RequestException with optional request and response objects to provide context about failed HTTP operations.
        
        Args:
            request: The original request object associated with the exception, used for debugging and retry logic.
            response: The response object received before the exception occurred, useful for inspecting server-side errors or status codes.
        """
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)


class InvalidJSONError(RequestException):
    """
    A JSON error occurred.
    """



class JSONDecodeError(InvalidJSONError, CompatJSONDecodeError):
    """
    Couldn't decode the text into json
    """


    def __init__(self, *args, **kwargs):
        """
        Initialize a JSON decoding error that preserves the original JSON-specific error details while ensuring compatibility with IOError semantics.
        
        This ensures that when a JSON parsing error occurs during HTTP response processing, the error message and context from the JSON decoder are preserved, while still maintaining compatibility with the error handling system used by Requests. This is critical for providing meaningful error feedback when dealing with malformed JSON responses from web APIs.
        
        Args:
            args: Positional arguments passed to the JSONDecodeError constructor, containing error details like the message, position, and JSON content.
            kwargs: Additional keyword arguments passed to the InvalidJSONError constructor, used for customizing error behavior or metadata.
        """
        CompatJSONDecodeError.__init__(self, *args)
        InvalidJSONError.__init__(self, *self.args, **kwargs)

    def __reduce__(self):
        """
        Ensures proper pickling behavior for JSONDecodeError instances by delegating to the original JSONDecodeError's __reduce__ method.
        
        This is necessary because the JSONDecodeError class expects all instantiation arguments during pickling, unlike the base IOError class. Without this override, the method resolution order (MRO) would incorrectly invoke IOError's __reduce__, which only accepts a single argument, leading to pickling failures. By explicitly using CompatJSONDecodeError's __reduce__, the full error context is preserved during serialization.
        
        Returns:
            A tuple or callable that defines how the object should be reconstructed during unpickling.
        """
        return CompatJSONDecodeError.__reduce__(self)


class HTTPError(RequestException):
    """
    An HTTP error occurred.
    """



class ConnectionError(RequestException):
    """
    A Connection error occurred.
    """



class ProxyError(ConnectionError):
    """
    A proxy error occurred.
    """



class SSLError(ConnectionError):
    """
    An SSL error occurred.
    """



class Timeout(RequestException):
    """
    The request exceeded the specified time limit and did not complete within the allowed duration.
    
        Catching this error will catch both
        :exc:`~requests.exceptions.ConnectTimeout` and
        :exc:`~requests.exceptions.ReadTimeout` errors.
    """



class ConnectTimeout(ConnectionError, Timeout):
    """
    The connection attempt to the remote server exceeded the specified timeout limit.
    
        Requests that produced this error are safe to retry.
    """



class ReadTimeout(Timeout):
    """
    The server did not send any data in the allotted amount of time.
    """



class URLRequired(RequestException):
    """
    A valid URL is required to make a request.
    """



class TooManyRedirects(RequestException):
    """
    Too many redirects.
    """



class MissingSchema(RequestException, ValueError):
    """
    The URL scheme (e.g. http or https) is missing.
    """



class InvalidSchema(RequestException, ValueError):
    """
    The URL scheme provided is either invalid or unsupported.
    """



class InvalidURL(RequestException, ValueError):
    """
    The URL provided was somehow invalid.
    """



class InvalidHeader(RequestException, ValueError):
    """
    The header value provided was somehow invalid.
    """



class InvalidProxyURL(InvalidURL):
    """
    The proxy URL provided is invalid.
    """



class ChunkedEncodingError(RequestException):
    """
    The server declared chunked encoding but sent an invalid chunk.
    """



class ContentDecodingError(RequestException, BaseHTTPError):
    """
    Failed to decode response content.
    """



class StreamConsumedError(RequestException, TypeError):
    """
    The content for this response was already consumed.
    """



class RetryError(RequestException):
    """
    Custom retries logic failed
    """



class UnrewindableBodyError(RequestException):
    """
    Requests encountered an error when trying to rewind a body.
    """



# Warnings


class RequestsWarning(Warning):
    """
    Base warning for Requests.
    """



class FileModeWarning(RequestsWarning, DeprecationWarning):
    """
    A file was opened in text mode, but Requests determined its binary length.
    """



class RequestsDependencyWarning(RequestsWarning):
    """
    An imported dependency doesn't match the expected version range.
    """

