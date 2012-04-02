# -*- coding: utf-8 -*-

"""
requests.session
~~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
requests (cookies, auth, proxies).

"""

from .defaults import defaults
from .models import Request
from .hooks import dispatch_hook
from .utils import header_expand
from .packages.urllib3.poolmanager import PoolManager


def merge_kwargs(local_kwarg, default_kwarg):
    """Merges kwarg dictionaries.

    If a local key in the dictionary is set to None, it will be removed.
    """

    if default_kwarg is None:
        return local_kwarg

    if isinstance(local_kwarg, str):
        return local_kwarg

    if local_kwarg is None:
        return default_kwarg

    # Bypass if not a dictionary (e.g. timeout)
    if not hasattr(default_kwarg, 'items'):
        return local_kwarg

    # Update new values.
    kwargs = default_kwarg.copy()
    kwargs.update(local_kwarg)

    # Remove keys that are set to None.
    for (k, v) in list(local_kwarg.items()):
        if v is None:
            del kwargs[k]

    return kwargs


class Session(object):
    """A Requests session."""

    __attrs__ = [
        'headers', 'cookies', 'auth', 'timeout', 'proxies', 'hooks',
        'params', 'config', 'verify', 'cert']


    def __init__(self,
        headers=None,
        cookies=None,
        auth=None,
        timeout=None,
        proxies=None,
        hooks=None,
        params=None,
        config=None,
        prefetch=False,
        verify=True,
        cert=None):

        self.headers = headers or {}
        self.cookies = cookies or {}
        self.auth = auth
        self.timeout = timeout
        self.proxies = proxies or {}
        self.hooks = hooks or {}
        self.params = params or {}
        self.config = config or {}
        self.prefetch = prefetch
        self.verify = verify
        self.cert = cert

        for (k, v) in list(defaults.items()):
            self.config.setdefault(k, v)

        self.init_poolmanager()

        # Set up a CookieJar to be used by default
        self.cookies = {}

        # Add passed cookies in.
        if cookies is not None:
            self.cookies.update(cookies)

    def init_poolmanager(self):
        self.poolmanager = PoolManager(
            num_pools=self.config.get('pool_connections'),
            maxsize=self.config.get('pool_maxsize')
        )

    def __repr__(self):
        return '<requests-client at 0x%x>' % (id(self))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def request(self, method, url,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        timeout=None,
        allow_redirects=True,
        proxies=None,
        hooks=None,
        return_response=True,
        config=None,
        prefetch=False,
        verify=None,
        cert=None):

        """Constructs and sends a :class:`Request <Request>`.
        Returns :class:`Response <Response>` object.

        :param method: method for the new :class:`Request` object.
        :param url: URL for the new :class:`Request` object.
        :param params: (optional) Dictionary or bytes to be sent in the query string for the :class:`Request`.
        :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
        :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
        :param cookies: (optional) Dict or CookieJar object to send with the :class:`Request`.
        :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
        :param auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
        :param timeout: (optional) Float describing the timeout of the request.
        :param allow_redirects: (optional) Boolean. Set to True by default.
        :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
        :param return_response: (optional) If False, an un-sent Request object will returned.
        :param config: (optional) A configuration dictionary.
        :param prefetch: (optional) if ``True``, the response content will be immediately downloaded.
        :param verify: (optional) if ``True``, the SSL cert will be verified. A CA_BUNDLE path can also be provided.
        :param cert: (optional) if String, path to ssl client cert file (.pem). If Tuple, ('cert', 'key') pair.
        """

        method = str(method).upper()

        # Default empty dicts for dict params.
        cookies = {} if cookies is None else cookies
        data = {} if data is None else data
        files = {} if files is None else files
        headers = {} if headers is None else headers
        params = {} if params is None else params
        hooks = {} if hooks is None else hooks
        prefetch = self.prefetch or prefetch

        # use session's hooks as defaults
        for key, cb in list(self.hooks.items()):
            hooks.setdefault(key, cb)

        # Expand header values.
        if headers:
            for k, v in list(headers.items()) or {}:
                headers[k] = header_expand(v)

        args = dict(
            method=method,
            url=url,
            data=data,
            params=params,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            hooks=hooks,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            config=config,
            verify=verify,
            cert=cert,
            _poolmanager=self.poolmanager
        )

        # Merge local kwargs with session kwargs.
        for attr in self.__attrs__:
            session_val = getattr(self, attr, None)
            local_val = args.get(attr)

            args[attr] = merge_kwargs(local_val, session_val)

        # Arguments manipulation hook.
        args = dispatch_hook('args', args['hooks'], args)

        # Create the (empty) response.
        r = Request(**args)

        # Give the response some context.
        r.session = self

        # Don't send if asked nicely.
        if not return_response:
            return r

        # Send the HTTP Request.
        r.send(prefetch=prefetch)

        # Send any cookies back up the to the session.
        self.cookies.update(r.response.cookies)

        # Return the response.
        return r.response


    def get(self, url, **kwargs):
        """Sends a GET request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        kwargs.setdefault('allow_redirects', True)
        return self.request('get', url, **kwargs)


    def options(self, url, **kwargs):
        """Sends a OPTIONS request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        kwargs.setdefault('allow_redirects', True)
        return self.request('options', url, **kwargs)


    def head(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        kwargs.setdefault('allow_redirects', False)
        return self.request('head', url, **kwargs)


    def post(self, url, data=None, **kwargs):
        """Sends a POST request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('post', url, data=data, **kwargs)


    def put(self, url, data=None, **kwargs):
        """Sends a PUT request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('put', url, data=data, **kwargs)


    def patch(self, url, data=None, **kwargs):
        """Sends a PATCH request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary or bytes to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('patch', url,  data=data, **kwargs)


    def delete(self, url, **kwargs):
        """Sends a DELETE request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('delete', url, **kwargs)

    def __getstate__(self):
        return dict((attr, getattr(self, attr, None)) for attr in self.__attrs__)

    def __setstate__(self, state):
        for attr, value in state.items():
            setattr(self, attr, value)

        self.init_poolmanager()


def session(**kwargs):
    """Returns a :class:`Session` for context-management."""

    return Session(**kwargs)
