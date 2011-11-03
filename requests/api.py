# -*- coding: utf-8 -*-

"""
requests.api
~~~~~~~~~~~~

This module implements the Requests API.

:copyright: (c) 2011 by Kenneth Reitz.
:license: ISC, see LICENSE for more details.

"""

from .sessions import session

__all__ = ('request', 'get', 'head', 'post', 'patch', 'put', 'delete')


def request(method, url,
    params=None,
    data=None,
    headers=None,
    cookies=None,
    files=None,
    auth=None,
    timeout=None,
    allow_redirects=False,
    proxies=None,
    hooks=None,
    return_response=True,
    config=None):
    """Constructs and sends a :class:`Request <Request>`.
    Returns :class:`Response <Response>` object.

    :param method: method for the new :class:`Request` object.
    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary or bytes to be sent in the query string for the :class:`Request`.
    :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
    :param cookies: (optional) Dict or CookieJar object to send with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param auth: (optional) Auth typle to enable Basic/Digest/Custom HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    :param allow_redirects: (optional) Boolean. Set to True if POST/PUT/DELETE redirect following is allowed.
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    :param return_response: (optional) If False, an un-sent Request object will returned.
    :param config: (optional) A configuration dictionary.
    """

    s = session()
    return s.request(
        method, url, params, data, headers, cookies, files, auth,
        timeout, allow_redirects, proxies, hooks, return_response,
        config
    )



def get(url, **kwargs):
    """Sends a GET request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param **kwargs: Optional arguments that ``request`` takes.
    """

    kwargs.setdefault('allow_redirects', True)
    return request('GET', url, **kwargs)


def head(url, **kwargs):
    """Sends a HEAD request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param **kwargs: Optional arguments that ``request`` takes.
    """

    kwargs.setdefault('allow_redirects', True)
    return request('HEAD', url, **kwargs)


def post(url, data='', **kwargs):
    """Sends a POST request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
    :param **kwargs: Optional arguments that ``request`` takes.
    """

    return request('post', url, data=data, **kwargs)


def put(url, data='', **kwargs):
    """Sends a PUT request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
    :param **kwargs: Optional arguments that ``request`` takes.
    """

    return request('put', url, data=data, **kwargs)


def patch(url, data='', **kwargs):
    """Sends a PATCH request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
    :param **kwargs: Optional arguments that ``request`` takes.
    """

    return request('patch', url,  data=data, **kwargs)


def delete(url, **kwargs):
    """Sends a DELETE request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param **kwargs: Optional arguments that ``request`` takes.
    """

    return request('delete', url, **kwargs)
