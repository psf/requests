# -*- coding: utf-8 -*-

"""
requests.api
~~~~~~~~~~~~

This module impliments the Requests API.

:copyright: (c) 2011 by Kenneth Reitz.
:license: ISC, see LICENSE for more details.

"""

import config
from .models import Request, Response, AuthManager, AuthObject, auth_manager


__all__ = ('request', 'get', 'head', 'post', 'patch', 'put', 'delete')

def request(method, url,
    params=None, data=None, headers=None, cookies=None, files=None, auth=None,
    timeout=None, allow_redirects=False, proxies=None):

    """Constructs and sends a :class:`Request <models.Request>`. Returns :class:`Response <models.Response>` object.

    :param method: method for the new :class:`Request` object.
    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary or bytes to be sent in the query string for the :class:`Request`.
    :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    :param allow_redirects: (optional) Boolean. Set to True if POST/PUT/DELETE redirect following is allowed.
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    """

    r = Request(
        method = method,
        url = url,
        data = data,
        params = params,
        headers = headers,
        cookiejar = cookies,
        files = files,
        auth = auth or auth_manager.get_auth(url),
        timeout = timeout or config.settings.timeout,
        allow_redirects = allow_redirects,
        proxies = proxies
    )

    r.send()

    return r.response


def get(url,
    params=None, headers=None, cookies=None, auth=None, timeout=None,
    proxies=None):

    """Sends a GET request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of parameters, or bytes, to be sent in the query string for the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    """

    return request('GET', url,
        params=params, headers=headers, cookies=cookies, auth=auth,
        timeout=timeout, proxies=proxies)


def head(url,
    params=None, headers=None, cookies=None, auth=None, timeout=None,
    proxies=None):

    """Sends a HEAD request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of parameters, or bytes, to be sent in the query string for the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    """

    return request('HEAD', url,
        params=params, headers=headers, cookies=cookies, auth=auth,
        timeout=timeout, proxies=proxies)


def post(url,
    data='', headers=None, files=None, cookies=None, auth=None, timeout=None,
    allow_redirects=False, params=None, proxies=None):

    """Sends a POST request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    :param allow_redirects: (optional) Boolean. Set to True if redirect following is allowed.
    :param params: (optional) Dictionary of parameters, or bytes, to be sent in the query string for the :class:`Request`.
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    """

    return request('POST', url,
        params=params, data=data, headers=headers, files=files,
        cookies=cookies, auth=auth, timeout=timeout,
        allow_redirects=allow_redirects, proxies=proxies)


def put(url, data='', headers=None, files=None, cookies=None, auth=None,
        timeout=None, allow_redirects=False, params=None, proxies=None):
    """Sends a PUT request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    :param allow_redirects: (optional) Boolean. Set to True if redirect following is allowed.
    :param params: (optional) Dictionary of parameters, or bytes, to be sent in the query string for the :class:`Request`.
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    """

    return request('PUT', url,
        params=params, data=data, headers=headers, files=files,
        cookies=cookies, auth=auth, timeout=timeout,
        allow_redirects=allow_redirects, proxies=proxies)


def patch(url, data='', headers=None, files=None, cookies=None, auth=None,
        timeout=None, allow_redirects=False, params=None, proxies=None):
    """Sends a PATCH request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    :param allow_redirects: (optional) Boolean. Set to True if redirect following is allowed.
    :param params: (optional) Dictionary of parameters, or bytes, to be sent in the query string for the :class:`Request`.
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    """

    return request('PATCH', url,
        params=params, data=data, headers=headers, files=files,
        cookies=cookies, auth=auth, timeout=timeout,
        allow_redirects=allow_redirects, proxies=proxies)


def delete(url,
    params=None, headers=None, cookies=None, auth=None, timeout=None,
    allow_redirects=False, proxies=None):

    """Sends a DELETE request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of parameters, or bytes, to be sent in the query string for the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    :param allow_redirects: (optional) Boolean. Set to True if redirect following is allowed.
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    """

    return request('DELETE', url,
        params=params, headers=headers, cookies=cookies, auth=auth,
        timeout=timeout, allow_redirects=allow_redirects, proxies=proxies)
