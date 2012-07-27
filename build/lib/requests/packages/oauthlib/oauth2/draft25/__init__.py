"""
oauthlib.oauth2.draft_25
~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for signing and checking OAuth 2.0 draft 25 requests.
"""
from tokens import prepare_bearer_uri, prepare_bearer_headers
from tokens import prepare_bearer_body, prepare_mac_header
from parameters import prepare_grant_uri, prepare_token_request
from parameters import parse_authorization_code_response
from parameters import parse_implicit_response, parse_token_response


AUTH_HEADER = u'auth_header'
URI_QUERY = u'query'
BODY = u'body'


class Client(object):

    def __init__(self, client_id,
            default_redirect_uri=None,
            token_type=None,
            access_token=None,
            refresh_token=None):
        """Initialize a client with commonly used attributes."""

        self.client_id = client_id
        self.default_redirect_uri = default_redirect_uri
        self.token_type = token_type
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_types = {
            u'bearer': self._add_bearer_token,
            u'mac': self._add_mac_token
        }

    def add_token(self, uri, http_method=u'GET', body=None, headers=None,
            token_placement=AUTH_HEADER):
        """Add token to the request uri, body or authorization header.

        The access token type provides the client with the information
        required to successfully utilize the access token to make a protected
        resource request (along with type-specific attributes).  The client
        MUST NOT use an access token if it does not understand the token
        type.

        For example, the "bearer" token type defined in
        [I-D.ietf-oauth-v2-bearer] is utilized by simply including the access
        token string in the request:

        GET /resource/1 HTTP/1.1
        Host: example.com
        Authorization: Bearer mF_9.B5f-4.1JqM

        while the "mac" token type defined in [I-D.ietf-oauth-v2-http-mac] is
        utilized by issuing a MAC key together with the access token which is
        used to sign certain components of the HTTP requests:

        GET /resource/1 HTTP/1.1
        Host: example.com
        Authorization: MAC id="h480djs93hd8",
                            nonce="274312:dj83hs9s",
                            mac="kDZvddkndxvhGRXZhvuDjEWhGeE="

        .. _`I-D.ietf-oauth-v2-bearer`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#ref-I-D.ietf-oauth-v2-bearer
        .. _`I-D.ietf-oauth-v2-http-mac`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#ref-I-D.ietf-oauth-v2-http-mac
        """
        return self.token_types[self.token_type](uri, http_method, body,
                    headers, token_placement)

    def prepare_refresh_body(self, body=u'', refresh_token=None, scope=None):
        """Prepare an access token request, using a refresh token.

        If the authorization server issued a refresh token to the client, the
        client makes a refresh request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format in the HTTP request entity-body:

        grant_type
                REQUIRED.  Value MUST be set to "refresh_token".
        refresh_token
                REQUIRED.  The refresh token issued to the client.
        scope
                OPTIONAL.  The scope of the access request as described by
                Section 3.3.  The requested scope MUST NOT include any scope
                not originally granted by the resource owner, and if omitted is
                treated as equal to the scope originally granted by the
                resource owner.
        """
        refresh_token = refresh_token or self.refresh_token
        return prepare_token_request(u'refresh_token', body=body, scope=scope,
                refresh_token=refresh_token)

    def _add_bearer_token(self, uri, http_method=u'GET', body=None,
            headers=None, token_placement=AUTH_HEADER):
        """Add a bearer token to the request uri, body or authorization header."""
        if token_placement == AUTH_HEADER:
            headers = prepare_bearer_headers(self.token, headers)

        if token_placement == URI_QUERY:
            uri = prepare_bearer_uri(self.token, uri)

        if token_placement == BODY:
            body = prepare_bearer_body(self.token, body)

        return uri, headers, body

    def _add_mac_token(self, uri, http_method=u'GET', body=None,
            headers=None, token_placement=AUTH_HEADER):
        """Add a MAC token to the request authorization header."""
        headers = prepare_mac_header(self.token, uri, self.key, http_method,
                        headers=headers, body=body, ext=self.ext,
                        hash_algorithm=self.hash_algorithm)
        return uri, headers, body

    def _populate_attributes(self, response):
        """Add commonly used values such as access_token to self."""

        if u'access_token' in response:
            self.access_token = response.get(u'access_token')

        if u'refresh_token' in response:
            self.refresh_token = response.get(u'refresh_token')

        if u'token_type' in response:
            self.token_type = response.get(u'token_type')

        if u'expires_in' in response:
            self.expires_in = response.get(u'expires_in')

        if u'code' in response:
            self.code = response.get(u'code')

    def prepare_request_uri(self, *args, **kwargs):
        """Abstract method used to create request URIs."""
        raise NotImplementedError("Must be implemented by inheriting classes.")

    def prepare_request_body(self, *args, **kwargs):
        """Abstract method used to create request bodies."""
        raise NotImplementedError("Must be implemented by inheriting classes.")

    def parse_request_uri_response(self, *args, **kwargs):
        """Abstract method used to parse redirection responses."""

    def parse_request_body_response(self, *args, **kwargs):
        """Abstract method used to parse JSON responses."""


class WebApplicationClient(Client):
    """A client utilizing the authorization code grant workflow.

    A web application is a confidential client running on a web
    server.  Resource owners access the client via an HTML user
    interface rendered in a user-agent on the device used by the
    resource owner.  The client credentials as well as any access
    token issued to the client are stored on the web server and are
    not exposed to or accessible by the resource owner.

    The authorization code grant type is used to obtain both access
    tokens and refresh tokens and is optimized for confidential clients.
    As a redirection-based flow, the client must be capable of
    interacting with the resource owner's user-agent (typically a web
    browser) and capable of receiving incoming requests (via redirection)
    from the authorization server.
    """

    def prepare_request_uri(self, uri, redirect_uri=None, scope=None,
            state=None, **kwargs):
        """Prepare the authorization code request URI

        The client constructs the request URI by adding the following
        parameters to the query component of the authorization endpoint URI
        using the "application/x-www-form-urlencoded" format as defined by
        [`W3C.REC-html401-19991224`_]:

        response_type
                REQUIRED.  Value MUST be set to "code".
        client_id
                REQUIRED.  The client identifier as described in `Section 2.2`_.
        redirect_uri
                OPTIONAL.  As described in `Section 3.1.2`_.
        scope
                OPTIONAL.  The scope of the access request as described by
                `Section 3.3`_.
        state
                RECOMMENDED.  An opaque value used by the client to maintain
                state between the request and callback.  The authorization
                server includes this value when redirecting the user-agent back
                to the client.  The parameter SHOULD be used for preventing
                cross-site request forgery as described in `Section 10.12`_.

        .. _`W3C.REC-html401-19991224`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#ref-W3C.REC-html401-19991224
        .. _`Section 2.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-2.2
        .. _`Section 3.1.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-3.1.2
        .. _`Section 3.3`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-3.3
        .. _`Section 10.12`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-10.12
        """
        redirect_uri = redirect_uri or self.default_redirect_uri
        return prepare_grant_uri(uri, self.client_id, u'code',
                redirect_uri=redirect_uri, scope=scope, state=state, **kwargs)

    def prepare_request_body(self, code, body=u'', redirect_uri=None, **kwargs):
        """Prepare the access token request body.

        The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format in the HTTP request entity-body:

        grant_type
                REQUIRED.  Value MUST be set to "authorization_code".
        code
                REQUIRED.  The authorization code received from the
                authorization server.
        redirect_uri
                REQUIRED, if the "redirect_uri" parameter was included in the
                authorization request as described in Section 4.1.1, and their
                values MUST be identical.

        .. _`Section 4.1.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.1.1
        """
        redirect_uri = redirect_uri or self.default_redirect_uri
        code = code or self.code
        return prepare_token_request(u'authorization_code', code=code, body=body,
                                         redirect_uri=redirect_uri, **kwargs)

    def parse_request_uri_response(self, uri, state=None):
        """Parse the URI query for code and state.

        If the resource owner grants the access request, the authorization
        server issues an authorization code and delivers it to the client by
        adding the following parameters to the query component of the
        redirection URI using the "application/x-www-form-urlencoded" format:

        code
                REQUIRED.  The authorization code generated by the
                authorization server.  The authorization code MUST expire
                shortly after it is issued to mitigate the risk of leaks.  A
                maximum authorization code lifetime of 10 minutes is
                RECOMMENDED.  The client MUST NOT use the authorization code
                more than once.  If an authorization code is used more than
                once, the authorization server MUST deny the request and SHOULD
                revoke (when possible) all tokens previously issued based on
                that authorization code.  The authorization code is bound to
                the client identifier and redirection URI.
        state
                REQUIRED if the "state" parameter was present in the client
                authorization request.  The exact value received from the
                client.
        """
        response = parse_authorization_code_response(uri, state=state)
        self._populate_attributes(response)
        return response

    def parse_request_body_response(self, body, scope=None):
        """Parse the JSON response body.

        If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token as described in `Section 5.1`_.  If the request client
        authentication failed or is invalid, the authorization server returns
        an error response as described in `Section 5.2`_.

        .. `Section 5.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.1
        .. `Section 5.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.2
        """
        response = parse_token_response(body, scope=scope)
        self._populate_attributes(response)
        return response


class UserAgentClient(Client):
    """A public client utilizing the implicit code grant workflow.

    A user-agent-based application is a public client in which the
    client code is downloaded from a web server and executes within a
    user-agent (e.g. web browser) on the device used by the resource
    owner.  Protocol data and credentials are easily accessible (and
    often visible) to the resource owner.  Since such applications
    reside within the user-agent, they can make seamless use of the
    user-agent capabilities when requesting authorization.

    The implicit grant type is used to obtain access tokens (it does not
    support the issuance of refresh tokens) and is optimized for public
    clients known to operate a particular redirection URI.  These clients
    are typically implemented in a browser using a scripting language
    such as JavaScript.

    As a redirection-based flow, the client must be capable of
    interacting with the resource owner's user-agent (typically a web
    browser) and capable of receiving incoming requests (via redirection)
    from the authorization server.

    Unlike the authorization code grant type in which the client makes
    separate requests for authorization and access token, the client
    receives the access token as the result of the authorization request.

    The implicit grant type does not include client authentication, and
    relies on the presence of the resource owner and the registration of
    the redirection URI.  Because the access token is encoded into the
    redirection URI, it may be exposed to the resource owner and other
    applications residing on the same device.
    """

    def prepare_request_uri(self, uri, redirect_uri=None, scope=None,
            state=None, **kwargs):
        """Prepare the implicit grant request URI.

        The client constructs the request URI by adding the following
        parameters to the query component of the authorization endpoint URI
        using the "application/x-www-form-urlencoded" format:

        response_type
                REQUIRED.  Value MUST be set to "token".
        client_id
                REQUIRED.  The client identifier as described in Section 2.2.
        redirect_uri
                OPTIONAL.  As described in Section 3.1.2.
        scope
                OPTIONAL.  The scope of the access request as described by
                Section 3.3.
        state
                RECOMMENDED.  An opaque value used by the client to maintain
                state between the request and callback.  The authorization
                server includes this value when redirecting the user-agent back
                to the client.  The parameter SHOULD be used for preventing
                cross-site request forgery as described in Section 10.12.
        """
        redirect_uri = redirect_uri or self.default_redirect_uri
        return prepare_grant_uri(uri, self.client_id, u'token',
                redirect_uri=redirect_uri, state=state, scope=scope, **kwargs)

    def parse_request_uri_response(self, uri, state=None, scope=None):
        """Parse the response URI fragment.

        If the resource owner grants the access request, the authorization
        server issues an access token and delivers it to the client by adding
        the following parameters to the fragment component of the redirection
        URI using the "application/x-www-form-urlencoded" format:

        access_token
                REQUIRED.  The access token issued by the authorization server.
        token_type
                REQUIRED.  The type of the token issued as described in
                `Section 7.1`_.  Value is case insensitive.
        expires_in
                RECOMMENDED.  The lifetime in seconds of the access token.  For
                example, the value "3600" denotes that the access token will
                expire in one hour from the time the response was generated.
                If omitted, the authorization server SHOULD provide the
                expiration time via other means or document the default value.
        scope
                OPTIONAL, if identical to the scope requested by the client,
                otherwise REQUIRED.  The scope of the access token as described
                by `Section 3.3`_.
        state
                REQUIRED if the "state" parameter was present in the client
                authorization request.  The exact value received from the
                client.

        .. _`Section 7.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-7.1
        .. _`Section 3.3`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-3.3
        """
        response = parse_implicit_response(uri, state=state, scope=scope)
        self._populate_attributes(response)
        return response


class NativeApplicationClient(Client):
    """A public client utilizing the client credentials grant workflow.

    A native application is a public client installed and executed on
    the device used by the resource owner.  Protocol data and
    credentials are accessible to the resource owner.  It is assumed
    that any client authentication credentials included in the
    application can be extracted.  On the other hand, dynamically
    issued credentials such as access tokens or refresh tokens can
    receive an acceptable level of protection.  At a minimum, these
    credentials are protected from hostile servers with which the
    application may interact with.  On some platforms these
    credentials might be protected from other applications residing on
    the same device.

    The client can request an access token using only its client
    credentials (or other supported means of authentication) when the
    client is requesting access to the protected resources under its
    control, or those of another resource owner which has been previously
    arranged with the authorization server (the method of which is beyond
    the scope of this specification).

    The client credentials grant type MUST only be used by confidential
    clients.

    Since the client authentication is used as the authorization grant,
    no additional authorization request is needed.
    """

    def prepare_request_body(self, body=u'', scope=None, **kwargs):
        """Add the client credentials to the request body.

        The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format in the HTTP request entity-body:

        grant_type
                REQUIRED.  Value MUST be set to "client_credentials".
        scope
                OPTIONAL.  The scope of the access request as described by
                `Section 3.3`_.

        .. _`Section 3.3`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-3.3
        """
        return prepare_token_request(u'client_credentials', body=body,
                                     scope=scope, **kwargs)

    def parse_request_body_response(self, body, scope=None):
        """Parse the JSON response body.

        If the access token request is valid and authorized, the
        authorization server issues an access token as described in
        `Section 5.1`_.  A refresh token SHOULD NOT be included.  If the request
        failed client authentication or is invalid, the authorization server
        returns an error response as described in `Section 5.2`_.

        .. `Section 5.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.1
        .. `Section 5.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.2
        """
        response = parse_token_response(body, scope=scope)
        self._populate_attributes(response)
        return response


class PasswordCredentialsClient(Client):
    """A public client using the resource owner password and username directly.

    The resource owner password credentials grant type is suitable in
    cases where the resource owner has a trust relationship with the
    client, such as the device operating system or a highly privileged
    application.  The authorization server should take special care when
    enabling this grant type, and only allow it when other flows are not
    viable.

    The grant type is suitable for clients capable of obtaining the
    resource owner's credentials (username and password, typically using
    an interactive form).  It is also used to migrate existing clients
    using direct authentication schemes such as HTTP Basic or Digest
    authentication to OAuth by converting the stored credentials to an
    access token.

    The method through which the client obtains the resource owner
    credentials is beyond the scope of this specification.  The client
    MUST discard the credentials once an access token has been obtained.
    """

    def prepare_request_body(self, username, password, body=u'', scope=None,
            **kwargs):
        """Add the resource owner password and username to the request body.

        The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format in the HTTP request entity-body:

        grant_type
                REQUIRED.  Value MUST be set to "password".
        username
                REQUIRED.  The resource owner username.
        password
                REQUIRED.  The resource owner password.
        scope
                OPTIONAL.  The scope of the access request as described by
                `Section 3.3`_.

        .. _`Section 3.3`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-3.3
        """
        return prepare_token_request(u'password', body=body, username=username,
                password=password, scope=scope, **kwargs)

    def parse_request_body_response(self, body, scope=None):
        """Parse the JSON response body.

        If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token as described in `Section 5.1`_.  If the request failed client
        authentication or is invalid, the authorization server returns an
        error response as described in `Section 5.2`_.

        .. `Section 5.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.1
        .. `Section 5.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.2
        """
        response = parse_token_response(body, scope=scope)
        self._populate_attributes(response)
        return response


class Server(object):
    pass
