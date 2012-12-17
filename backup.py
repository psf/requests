
    def old_request(self, method, url,
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
        prefetch=None,
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
        :param auth: (optional) Auth tuple or callable to enable Basic/Digest/Custom HTTP Auth.
        :param timeout: (optional) Float describing the timeout of the request.
        :param allow_redirects: (optional) Boolean. Set to True by default.
        :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
        :param return_response: (optional) If False, an un-sent Request object will returned.
        :param config: (optional) A configuration dictionary. See ``request.defaults`` for allowed keys and their default values.
        :param prefetch: (optional) whether to immediately download the response content. Defaults to ``True``.
        :param verify: (optional) if ``True``, the SSL cert will be verified. A CA_BUNDLE path can also be provided.
        :param cert: (optional) if String, path to ssl client cert file (.pem). If Tuple, ('cert', 'key') pair.
        """

        method = str(method).upper()

        # Default empty dicts for dict params.
        data = [] if data is None else data
        files = [] if files is None else files
        headers = {} if headers is None else headers
        params = {} if params is None else params
        hooks = {} if hooks is None else hooks
        prefetch = prefetch if prefetch is not None else self.prefetch

        # use session's hooks as defaults
        for key, cb in list(self.hooks.items()):
            hooks.setdefault(key, cb)

        # Expand header values.
        if headers:
            for k, v in list(headers.items() or {}):
                headers[k] = header_expand(v)

        args = dict(
            method=method,
            url=url,
            data=data,
            params=from_key_val_list(params),
            headers=from_key_val_list(headers),
            cookies=cookies,
            files=files,
            auth=auth,
            hooks=from_key_val_list(hooks),
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=from_key_val_list(proxies),
            config=from_key_val_list(config),
            prefetch=prefetch,
            verify=verify,
            cert=cert,
            _poolmanager=self.poolmanager
        )

        # merge session cookies into passed-in ones
        dead_cookies = None
        # passed-in cookies must become a CookieJar:
        if not isinstance(cookies, cookielib.CookieJar):
            args['cookies'] = cookiejar_from_dict(cookies)
            # support unsetting cookies that have been passed in with None values
            # this is only meaningful when `cookies` is a dict ---
            # for a real CookieJar, the client should use session.cookies.clear()
            if cookies is not None:
                dead_cookies = [name for name in cookies if cookies[name] is None]
        # merge the session's cookies into the passed-in cookies:
        for cookie in self.cookies:
            args['cookies'].set_cookie(cookie)
        # remove the unset cookies from the jar we'll be using with the current request
        # (but not from the session's own store of cookies):
        if dead_cookies is not None:
            for name in dead_cookies:
                remove_cookie_by_name(args['cookies'], name)

        # Merge local kwargs with session kwargs.
        for attr in self.__attrs__:
            # we already merged cookies:
            if attr == 'cookies':
                continue

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
        return self._send_request(r, **args)


class OldRequest(object):
    """The :class:`Request <Request>` object. It carries out all functionality
    of Requests. Recommended interface is with the Requests functions.
    """

    def __init__(self,
        url=None,
        headers=dict(),
        files=None,
        method=None,
        data=dict(),
        params=dict(),
        auth=None,
        cookies=None,
        timeout=None,
        redirect=False,
        allow_redirects=False,
        proxies=None,
        hooks=None,
        config=None,
        prefetch=True,
        _poolmanager=None,
        verify=None,
        session=None,
        cert=None):

        #: Dictionary of configurations for this request.
        self.config = dict(config or [])

        #: Float describes the timeout of the request.
        #  (Use socket.setdefaulttimeout() as fallback)
        self.timeout = timeout

        # URL

        #: Dictionary of HTTP Headers to attach to the :class:`Request <Request>`.
        self.headers = dict(headers or [])

        #: Dictionary of files to multipart upload (``{filename: content}``).
        self.files = None

        #: HTTP Method to use.
        self.method = method

        #: Dictionary, bytes or file stream of request body data to attach to the
        #: :class:`Request <Request>`.
        self.data = None

        #: Dictionary of querystring data to attach to the
        #: :class:`Request <Request>`. The dictionary values can be lists for representing
        #: multivalued query parameters.
        self.params = None

        #: True if :class:`Request <Request>` is part of a redirect chain (disables history
        #: and HTTPError storage).
        self.redirect = redirect

        #: Set to True if full redirects are allowed (e.g. re-POST-ing of data at new ``Location``)
        self.allow_redirects = allow_redirects

        # Dictionary mapping protocol to the URL of the proxy (e.g. {'http': 'foo.bar:3128'})
        self.proxies = dict(proxies or [])

        for proxy_type, uri_ref in list(self.proxies.items()):
            if not uri_ref:
                del self.proxies[proxy_type]

        # If no proxies are given, allow configuration by environment variables
        # HTTP_PROXY and HTTPS_PROXY.
        if not self.proxies and self.config.get('trust_env'):
            self.proxies = get_environ_proxies(self.url)

        self.data = data
        self.params = params
        self.files = files

        #: :class:`Response <Response>` instance, containing
        #: content and metadata of HTTP Response, once :attr:`sent <send>`.
        self.response = Response()

        #: Authentication tuple or object to attach to :class:`Request <Request>`.
        self.auth = auth

        # #: CookieJar to attach to :class:`Request <Request>`.
        # if isinstance(cookies, cookielib.CookieJar):
        #     self.cookies = cookies
        # else:
        #     self.cookies = cookiejar_from_dict(cookies)

        #: True if Request has been sent.
        self.sent = False

        #: Event-handling hooks.
        self.hooks = {}

        for event in HOOKS:
            self.hooks[event] = []

        hooks = hooks or {}

        for (k, v) in list(hooks.items()):
            self.register_hook(event=k, hook=v)

        #: Session.
        self.session = session

        #: SSL Verification.
        self.verify = verify

        #: SSL Certificate
        self.cert = cert

        #: Prefetch response content
        self.prefetch = prefetch

        # if headers:
        #     headers = CaseInsensitiveDict(self.headers)
        # else:
        #     headers = CaseInsensitiveDict()

        # Add configured base headers.
        for (k, v) in list(self.config.get('base_headers', {}).items()):
            if k not in headers:
                headers[k] = v

        self.headers = headers
        self._poolmanager = _poolmanager

    def __repr__(self):
        return '<Request [%s]>' % (self.method)

    def _build_response(self, resp):
        """Build internal :class:`Response <Response>` object
        from given response.
        """

        def build(resp):

            response = Response()

            # Pass settings over.
            response.config = self.config

            if resp:

                # Fallback to None if there's no status_code, for whatever reason.
                # response.status_code = getattr(resp, 'status', None)

                # Make headers case-insensitive.
                # response.headers = CaseInsensitiveDict(getattr(resp, 'headers', {}))

                # Set encoding.
                # response.encoding = get_encoding_from_headers(response.headers)

                # Add new cookies from the server.
                extract_cookies_to_jar(self.cookies, self, resp)

                # Save cookies in Response.
                response.cookies = self.cookies

                # Save cookies in Session.
                for cookie in self.cookies:
                    self.session.cookies.set_cookie(cookie)

                # No exceptions were harmed in the making of this request.
                response.error = getattr(resp, 'error', None)

            # Save original response for later.
            response.raw = resp
            if isinstance(self.full_url, bytes):
                response.url = self.full_url.decode('utf-8')
            else:
                response.url = self.full_url

            return response

        history = []

        r = build(resp)
        # TODO: session level shit
        if r.status_code in REDIRECT_STATI and not self.redirect:

            while (('location' in r.headers and r.status_code in REDIRECT_STATI) and
                   ((r.status_code is codes.see_other) or (self.allow_redirects))):

                r.content  # Consume socket so it can be released

                if not len(history) < self.config.get('max_redirects'):
                    raise TooManyRedirects()

                # Release the connection back into the pool.
                r.raw.release_conn()

                history.append(r)

                url = r.headers['location']
                data = self.data
                files = self.files

                # Handle redirection without scheme (see: RFC 1808 Section 4)
                if url.startswith('//'):
                    parsed_rurl = urlparse(r.url)
                    url = '%s:%s' % (parsed_rurl.scheme, url)

                # Facilitate non-RFC2616-compliant 'location' headers
                # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
                if not urlparse(url).netloc:
                    url = urljoin(r.url,
                                  # Compliant with RFC3986, we percent
                                  # encode the url.
                                  requote_uri(url))

                # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.4
                if r.status_code is codes.see_other:
                    method = 'GET'
                    data = None
                    files = None
                else:
                    method = self.method

                # Do what the browsers do, despite standards...
                if r.status_code in (codes.moved, codes.found) and self.method == 'POST':
                    method = 'GET'
                    data = None
                    files = None

                if (r.status_code == 303) and self.method != 'HEAD':
                    method = 'GET'
                    data = None
                    files = None

                # Remove the cookie headers that were sent.
                headers = self.headers
                try:
                    del headers['Cookie']
                except KeyError:
                    pass

                request = Request(
                    url=url,
                    headers=headers,
                    files=files,
                    method=method,
                    params=self.session.params,
                    auth=self.auth,
                    cookies=self.cookies,
                    redirect=True,
                    data=data,
                    config=self.config,
                    timeout=self.timeout,
                    _poolmanager=self._poolmanager,
                    proxies=self.proxies,
                    verify=self.verify,
                    session=self.session,
                    cert=self.cert,
                    prefetch=self.prefetch
                )

                request.send()
                r = request.response

            r.history = history

        self.response = r
        self.response.request = self


    def register_hook(self, event, hook):
        """Properly register a hook."""
        if isinstance(hook, collections.Callable):
            self.hooks[event].append(hook)
        elif hasattr(hook, '__iter__'):
            self.hooks[event].extend(h for h in hook if isinstance(h, collections.Callable))

    def deregister_hook(self, event, hook):
        """Deregister a previously registered hook.
        Returns True if the hook existed, False if not.
        """

        try:
            self.hooks[event].remove(hook)
            return True
        except ValueError:
            return False

    def send(self, anyway=False, prefetch=None):
        """Sends the request. Returns True if successful, False if not.
        If there was an HTTPError during transmission,
        self.response.status_code will contain the HTTPError code.

        Once a request is successfully sent, `sent` will equal True.

        :param anyway: If True, request will be sent, even if it has
        already been sent.

        :param prefetch: If not None, will override the request's own setting
        for prefetch.
        """

        # Build the URL
        url = self.full_url

        # Pre-request hook.
        r = dispatch_hook('pre_request', self.hooks, self)
        self.__dict__.update(r.__dict__)

        # Logging
        log.info('Sending %s: %s' % (self, url))

        # Use .netrc auth if none was provided.
        if not self.auth and self.config.get('trust_env'):
            self.auth = get_netrc_auth(url)

        # if self.auth:
        #     if isinstance(self.auth, tuple) and len(self.auth) == 2:
        #         # special-case basic HTTP auth
        #         self.auth = HTTPBasicAuth(*self.auth)

        #     # Allow auth to make its changes.
        #     r = self.auth(self)

        #     # Update self to reflect the auth changes.
        #     self.__dict__.update(r.__dict__)

        # # Nottin' on you.
        # body = None
        # content_type = None

        # # Multi-part file uploads.
        # if self.files:
        #     (body, content_type) = self._encode_files(self.files)
        # else:
        #     if self.data:

        #         body = self._encode_params(self.data)
        #         if isinstance(self.data, str) or isinstance(self.data, builtin_str) or hasattr(self.data, 'read'):
        #             content_type = None
        #         else:
        #             content_type = 'application/x-www-form-urlencoded'

        # self.headers['Content-Length'] = '0'
        # if hasattr(body, 'seek') and hasattr(body, 'tell'):
        #     body.seek(0, 2)
        #     self.headers['Content-Length'] = str(body.tell())
        #     body.seek(0, 0)
        # elif body is not None:
        #     self.headers['Content-Length'] = str(len(body))

        # # Add content-type if it wasn't explicitly provided.
        # if (content_type) and (not 'content-type' in self.headers):
        #     self.headers['Content-Type'] = content_type

        _p = urlparse(url)
        no_proxy = filter(lambda x: x.strip(), self.proxies.get('no', '').split(','))
        proxy = self.proxies.get(_p.scheme)

        if proxy and not any(map(_p.hostname.endswith, no_proxy)):
            conn = poolmanager.ProxyManager(self.get_connection_for_url(proxy))
            _proxy = urlparse(proxy)
            if '@' in _proxy.netloc:
                auth, url = _proxy.netloc.split('@', 1)
                self.proxy_auth = HTTPProxyAuth(*auth.split(':', 1))
                r = self.proxy_auth(self)
                self.__dict__.update(r.__dict__)
        else:
            conn = self.get_connection_for_url(url)

        if not self.config.get('keep_alive'):
            self.headers['Connection'] = 'close'

        # if url.startswith('https') and self.verify:

        #     cert_loc = None

        #     # Allow self-specified cert location.
        #     if self.verify is not True:
        #         cert_loc = self.verify

        #     # Look for configuration.
        #     if not cert_loc and self.config.get('trust_env'):
        #         cert_loc = os.environ.get('REQUESTS_CA_BUNDLE')

        #     # Curl compatibility.
        #     if not cert_loc and self.config.get('trust_env'):
        #         cert_loc = os.environ.get('CURL_CA_BUNDLE')

        #     if not cert_loc:
        #         cert_loc = DEFAULT_CA_BUNDLE_PATH

        #     if not cert_loc:
        #         raise Exception("Could not find a suitable SSL CA certificate bundle.")

        #     conn.cert_reqs = 'CERT_REQUIRED'
        #     conn.ca_certs = cert_loc
        # else:
        #     conn.cert_reqs = 'CERT_NONE'
        #     conn.ca_certs = None

        # if self.cert:
        #     if len(self.cert) == 2:
        #         conn.cert_file = self.cert[0]
        #         conn.key_file = self.cert[1]
        #     else:
        #         conn.cert_file = self.cert

        if not self.sent or anyway:

            # Skip if 'cookie' header is explicitly set.
            # if 'cookie' not in self.headers:
            #     cookie_header = get_cookie_header(self.cookies, self)
            #     if cookie_header is not None:
            #         self.headers['Cookie'] = cookie_header

            # Pre-send hook.
            r = dispatch_hook('pre_send', self.hooks, self)
            self.__dict__.update(r.__dict__)

            # catch urllib3 exceptions and throw Requests exceptions
            # try:
            #     # Send the request.
            #     r = conn.urlopen(
            #         method=self.method,
            #         url=self.path_url,
            #         body=body,
            #         headers=self.headers,
            #         redirect=False,
            #         assert_same_host=False,
            #         preload_content=False,
            #         decode_content=False,
            #         retries=self.config.get('max_retries', 0),
            #         timeout=self.timeout,
            #     )
            #     self.sent = True

            # except socket.error as sockerr:
            #     raise ConnectionError(sockerr)

            # except MaxRetryError as e:
            #     raise ConnectionError(e)

            # except (_SSLError, _HTTPError) as e:
            #     if isinstance(e, _SSLError):
            #         raise SSLError(e)
            #     elif isinstance(e, TimeoutError):
            #         raise Timeout(e)
            #     else:
            #         raise Timeout('Request timed out.')

            # build_response can throw TooManyRedirects
            self._build_response(r)

            # Response manipulation hook.
            self.response = dispatch_hook('response', self.hooks, self.response)

            # Post-request hook.
            r = dispatch_hook('post_request', self.hooks, self)
            self.__dict__.update(r.__dict__)

            # If prefetch is True, mark content as consumed.
            if prefetch is None:
                prefetch = self.prefetch
            if prefetch:
                # Save the response.
                self.response.content

            return self.sent

    def get_connection_for_url(self, url):
        # Check to see if keep_alive is allowed.
        try:
            if self.config.get('keep_alive'):
                conn = self._poolmanager.connection_from_url(url)
            else:
                conn = connectionpool.connection_from_url(url)
            return conn
        except LocationParseError as e:
            raise InvalidURL(e)

    def prepare(self):
        return deepcopy(self)