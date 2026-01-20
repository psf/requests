"""
requests.api
~~~~~~~~~~~~

This module implements the Requests API.

:copyright: (c) 2012 by Kenneth Reitz.
:license: Apache2, see LICENSE for more details.
"""

from . import sessions


def request(method, url, **kwargs):
    """
    Constructs and sends an HTTP request using a session-based approach for reliable and efficient HTTP communication.
    
    Args:
        method: The HTTP method to use for the request (e.g., GET, POST, PUT, DELETE).
        url: The URL to which the request is sent.
        params: Optional query parameters to include in the URL.
        data: Optional data to send in the request body (form-encoded).
        json: Optional JSON data to send in the request body (automatically serialized).
        headers: Optional HTTP headers to include in the request.
        cookies: Optional cookies to send with the request.
        files: Optional file data for multipart encoding uploads.
        auth: Optional authentication credentials (e.g., username/password).
        timeout: Optional timeout for the request (in seconds or as a tuple for connect/read timeouts).
        allow_redirects: Whether to follow HTTP redirects automatically.
        proxies: Optional proxy configuration for the request.
        verify: Whether to verify SSL certificates (True, False, or path to CA bundle).
        stream: Whether to stream the response content instead of downloading it immediately.
        cert: Optional SSL client certificate (path or ('cert', 'key') tuple).
    
    Returns:
        A Response object containing the server's response, including status code, headers, and content.
    
    This function is the core interface for making HTTP requests in the Requests library, designed to simplify web interactions by abstracting low-level details like connection handling, encoding, and session management. It enables developers to easily interact with web APIs, scrape websites, and perform authenticated requests with minimal boilerplate code.
    """

    # By using the 'with' statement we are sure the session is closed, thus we
    # avoid leaving sockets open which can trigger a ResourceWarning in some
    # cases, and look like a memory leak in others.
    with sessions.Session() as session:
        return session.request(method=method, url=url, **kwargs)


def get(url, params=None, **kwargs):
    """
    Sends an HTTP GET request to retrieve data from a web service or API endpoint.
    
    This function is the primary interface for fetching resources over HTTP in the Requests library, enabling developers to easily interact with web APIs and retrieve data in a simple, readable way. It abstracts away the complexity of low-level HTTP handling, allowing users to focus on working with the data rather than managing connections, headers, or encoding.
    
    Args:
        url: The URL of the resource to fetch.
        params: Optional dictionary, list of tuples, or bytes to include in the query string.
        **kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeouts.
    
    Returns:
        A Response object containing the server's response, including status code, headers, and content.
    """
    r"""Sends a GET request.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary, list of tuples or bytes to send
        in the query string for the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """

    return request("get", url, params=params, **kwargs)


def options(url, **kwargs):
    """
    Sends an HTTP OPTIONS request to discover the communication options available for a resource, which is useful for debugging APIs and understanding supported methods and headers.
    
    Args:
        url: The URL to send the OPTIONS request to.
        **kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeouts.
    
    Returns:
        A Response object containing the server's response to the OPTIONS request, including status code, headers, and body.
    """
    r"""Sends an OPTIONS request.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """

    return request("options", url, **kwargs)


def head(url, **kwargs):
    """
    Sends an HTTP HEAD request to retrieve resource metadata without downloading the body, which is useful for checking resource availability, size, or headers efficiently.
    
    Args:
        url: The URL to send the HEAD request to.
        **kwargs: Additional arguments passed to the underlying request method. If `allow_redirects` is not specified, it defaults to `False` to prevent automatic following of redirects, ensuring the response reflects the initial request behavior.
    
    Returns:
        A Response object containing the server's response headers and status code, enabling inspection of resource metadata without transferring the full content.
    """
    r"""Sends a HEAD request.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes. If
        `allow_redirects` is not provided, it will be set to `False` (as
        opposed to the default :meth:`request` behavior).
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """

    kwargs.setdefault("allow_redirects", False)
    return request("head", url, **kwargs)


def post(url, data=None, json=None, **kwargs):
    """
    Sends an HTTP POST request to the specified URL, enabling easy interaction with web APIs and services.
    
    Args:
        url: The target URL to send the POST request to.
        data: Optional data to send in the request body, which can be a dictionary, list of tuples, bytes, or a file-like object.
        json: Optional JSON-serializable object to send in the request body; if provided, it takes precedence over `data`.
        **kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeout settings.
    
    Returns:
        A Response object containing the server's response, including status code, headers, and response body, allowing for easy handling of API responses and error checking.
    """
    r"""Sends a POST request.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param json: (optional) A JSON serializable Python object to send in the body of the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """

    return request("post", url, data=data, json=json, **kwargs)


def put(url, data=None, **kwargs):
    """
    Sends a PUT request to update or replace a resource on a web server.
    
    This function is part of the Requests library, which provides a simple and intuitive interface for making HTTP requests in Python. PUT is used to send data to a server to create or update a resource at a specific URL, making it essential for interacting with RESTful APIs and managing stateful web services.
    
    Args:
        url: The URL of the resource to update or replace.
        data: Optional data to send in the body of the request, such as a dictionary, list of tuples, bytes, or file-like object.
        json: Optional JSON-serializable object to send in the body of the request; if provided, it takes precedence over `data`.
        **kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeout settings.
    
    Returns:
        A Response object containing the server's response to the PUT request, including status code, headers, and response body.
    """
    r"""Sends a PUT request.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param json: (optional) A JSON serializable Python object to send in the body of the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """

    return request("put", url, data=data, **kwargs)


def patch(url, data=None, **kwargs):
    """
    Sends an HTTP PATCH request to update resources on a web server, enabling partial updates to existing data in a RESTful API.
    
    Args:
        url: The URL of the resource to update.
        data: Optional data to send in the body of the request, such as a dictionary, list of tuples, bytes, or file-like object.
        json: Optional JSON-serializable object to send in the body of the request, automatically encoded as JSON.
        **kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeout settings.
    
    Returns:
        A Response object containing the server's response to the PATCH request, including status code, headers, and response body.
    """
    r"""Sends a PATCH request.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param json: (optional) A JSON serializable Python object to send in the body of the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """

    return request("patch", url, data=data, **kwargs)


def delete(url, **kwargs):
    """
    Sends an HTTP DELETE request to remove a resource from the specified URL.
    
    This function is part of the Requests library, which provides a simple and intuitive interface for making HTTP requests in Python. It abstracts the complexity of low-level HTTP interactions, allowing developers to easily delete resources from web services—commonly used in RESTful APIs for resource cleanup or data removal.
    
    Args:
        url: The URL of the resource to delete.
        **kwargs: Additional arguments passed to the underlying request method, such as headers, authentication, or timeout settings.
    
    Returns:
        A Response object containing the server's response to the DELETE request.
    """
    r"""Sends a DELETE request.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """

    return request("delete", url, **kwargs)
