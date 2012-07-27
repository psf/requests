# -*- coding: utf-8 -*-
from __future__ import absolute_import

"""
oauthlib.oauth1.rfc5849
~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for signing and checking OAuth 1.0 RFC 5849 requests.
"""

import logging
import time
import urlparse

from oauthlib.common import Request, urlencode, generate_nonce
from oauthlib.common import generate_timestamp
from . import parameters, signature, utils

SIGNATURE_HMAC = u"HMAC-SHA1"
SIGNATURE_RSA = u"RSA-SHA1"
SIGNATURE_PLAINTEXT = u"PLAINTEXT"
SIGNATURE_METHODS = (SIGNATURE_HMAC, SIGNATURE_RSA, SIGNATURE_PLAINTEXT)

SIGNATURE_TYPE_AUTH_HEADER = u'AUTH_HEADER'
SIGNATURE_TYPE_QUERY = u'QUERY'
SIGNATURE_TYPE_BODY = u'BODY'

CONTENT_TYPE_FORM_URLENCODED = u'application/x-www-form-urlencoded'


class Client(object):
    """A client used to sign OAuth 1.0 RFC 5849 requests"""
    def __init__(self, client_key,
            client_secret=None,
            resource_owner_key=None,
            resource_owner_secret=None,
            callback_uri=None,
            signature_method=SIGNATURE_HMAC,
            signature_type=SIGNATURE_TYPE_AUTH_HEADER,
            rsa_key=None, verifier=None):
        self.client_key = client_key
        self.client_secret = client_secret
        self.resource_owner_key = resource_owner_key
        self.resource_owner_secret = resource_owner_secret
        self.signature_method = signature_method
        self.signature_type = signature_type
        self.callback_uri = callback_uri
        self.rsa_key = rsa_key
        self.verifier = verifier

        if self.signature_method == SIGNATURE_RSA and self.rsa_key is None:
            raise ValueError('rsa_key is required when using RSA signature method.')

    def get_oauth_signature(self, request):
        """Get an OAuth signature to be used in signing a request
        """
        if self.signature_method == SIGNATURE_PLAINTEXT:
            # fast-path
            return signature.sign_plaintext(self.client_secret,
                self.resource_owner_secret)

        uri, headers, body = self._render(request)

        collected_params = signature.collect_parameters(
            uri_query=urlparse.urlparse(uri).query,
            body=body,
            headers=headers)
        logging.debug("Collected params: {0}".format(collected_params))

        normalized_params = signature.normalize_parameters(collected_params)
        normalized_uri = signature.normalize_base_string_uri(request.uri)
        logging.debug("Normalized params: {0}".format(normalized_params))
        logging.debug("Normalized URI: {0}".format(normalized_uri))

        base_string = signature.construct_base_string(request.http_method,
            normalized_uri, normalized_params)

        logging.debug("Base signing string: {0}".format(base_string))

        if self.signature_method == SIGNATURE_HMAC:
            sig = signature.sign_hmac_sha1(base_string, self.client_secret,
                self.resource_owner_secret)
        elif self.signature_method == SIGNATURE_RSA:
            sig = signature.sign_rsa_sha1(base_string, self.rsa_key)
        else:
            sig = signature.sign_plaintext(self.client_secret,
                self.resource_owner_secret)

        logging.debug("Signature: {0}".format(sig))
        return sig

    def get_oauth_params(self):
        """Get the basic OAuth parameters to be used in generating a signature.
        """
        params = [
            (u'oauth_nonce', generate_nonce()),
            (u'oauth_timestamp', generate_timestamp()),
            (u'oauth_version', u'1.0'),
            (u'oauth_signature_method', self.signature_method),
            (u'oauth_consumer_key', self.client_key),
        ]
        if self.resource_owner_key:
            params.append((u'oauth_token', self.resource_owner_key))
        if self.callback_uri:
            params.append((u'oauth_callback', self.callback_uri))
        if self.verifier:
            params.append((u'oauth_verifier', self.verifier))

        return params

    def _render(self, request, formencode=False):
        """Render a signed request according to signature type

        Returns a 3-tuple containing the request URI, headers, and body.

        If the formencode argument is True and the body contains parameters, it
        is escaped and returned as a valid formencoded string.
        """
        # TODO what if there are body params on a header-type auth?
        # TODO what if there are query params on a body-type auth?

        uri, headers, body = request.uri, request.headers, request.body

        # TODO: right now these prepare_* methods are very narrow in scope--they
        # only affect their little thing. In some cases (for example, with
        # header auth) it might be advantageous to allow these methods to touch
        # other parts of the request, like the headers—so the prepare_headers
        # method could also set the Content-Type header to x-www-form-urlencoded
        # like the spec requires. This would be a fundamental change though, and
        # I'm not sure how I feel about it.
        if self.signature_type == SIGNATURE_TYPE_AUTH_HEADER:
            headers = parameters.prepare_headers(request.oauth_params, request.headers)
        elif self.signature_type == SIGNATURE_TYPE_BODY and request.decoded_body is not None:
            body = parameters.prepare_form_encoded_body(request.oauth_params, request.decoded_body)
            if formencode:
                body = urlencode(body)
            headers['Content-Type'] = u'application/x-www-form-urlencoded'
        elif self.signature_type == SIGNATURE_TYPE_QUERY:
            uri = parameters.prepare_request_uri_query(request.oauth_params, request.uri)
        else:
            raise ValueError('Unknown signature type specified.')

        return uri, headers, body

    def sign(self, uri, http_method=u'GET', body=None, headers=None):
        """Sign a request

        Signs an HTTP request with the specified parts.

        Returns a 3-tuple of the signed request's URI, headers, and body.
        Note that http_method is not returned as it is unaffected by the OAuth
        signing process.

        The body argument may be a dict, a list of 2-tuples, or a formencoded
        string. The Content-Type header must be 'application/x-www-form-urlencoded'
        if it is present.

        If the body argument is not one of the above, it will be returned
        verbatim as it is unaffected by the OAuth signing process. Attempting to
        sign a request with non-formencoded data using the OAuth body signature
        type is invalid and will raise an exception.

        If the body does contain parameters, it will be returned as a properly-
        formatted formencoded string.

        All string data MUST be unicode. This includes strings inside body
        dicts, for example.
        """
        # normalize request data
        request = Request(uri, http_method, body, headers)

        # sanity check
        content_type = request.headers.get('Content-Type', None)
        multipart = content_type and content_type.startswith('multipart/')
        should_have_params = content_type == CONTENT_TYPE_FORM_URLENCODED
        has_params = request.decoded_body is not None
        # 3.4.1.3.1.  Parameter Sources
        # [Parameters are collected from the HTTP request entity-body, but only
        # if [...]:
        #    *  The entity-body is single-part.
        if multipart and has_params:
            raise ValueError("Headers indicate a multipart body but body contains parameters.")
        #    *  The entity-body follows the encoding requirements of the
        #       "application/x-www-form-urlencoded" content-type as defined by
        #       [W3C.REC-html40-19980424].
        elif should_have_params and not has_params:
            raise ValueError("Headers indicate a formencoded body but body was not decodable.")
        #    *  The HTTP request entity-header includes the "Content-Type"
        #       header field set to "application/x-www-form-urlencoded".
        elif not should_have_params and has_params:
            raise ValueError("Body contains parameters but Content-Type header was not set.")

        # 3.5.2.  Form-Encoded Body
        # Protocol parameters can be transmitted in the HTTP request entity-
        # body, but only if the following REQUIRED conditions are met:
        # o  The entity-body is single-part.
        # o  The entity-body follows the encoding requirements of the
        #    "application/x-www-form-urlencoded" content-type as defined by
        #    [W3C.REC-html40-19980424].
        # o  The HTTP request entity-header includes the "Content-Type" header
        #    field set to "application/x-www-form-urlencoded".
        elif self.signature_type == SIGNATURE_TYPE_BODY and not (
                should_have_params and has_params and not multipart):
            raise ValueError('Body signatures may only be used with form-urlencoded content')

        # generate the basic OAuth parameters
        request.oauth_params = self.get_oauth_params()

        # generate the signature
        request.oauth_params.append((u'oauth_signature', self.get_oauth_signature(request)))

        # render the signed request and return it
        return self._render(request, formencode=True)


class Server(object):
    """A server base class used to verify OAuth 1.0 RFC 5849 requests

    OAuth providers should inherit from Server and implement the methods
    and properties outlined below. Further details are provided in the
    documentation for each method and property.

    Methods used to check the format of input parameters. Common tests include
    length, character set, membership, range or pattern. These tests are
    referred to as `whitelisting or blacklisting`_. Whitelisting is better
    but blacklisting can be usefull to spot malicious activity.
    The following have methods a default implementation:

    - check_client_key
    - check_request_token
    - check_access_token
    - check_nonce
    - check_verifier
    - check_realm

    The methods above default to whitelist input parameters, checking that they
    are alphanumerical and between a minimum and maximum length. Rather than
    overloading the methods a few properties can be used to configure these
    methods.

    @ safe_characters -> (character set)
    @ client_key_length -> (min, max)
    @ request_token_length -> (min, max)
    @ access_token_length -> (min, max)
    @ nonce_length -> (min, max)
    @ verifier_length -> (min, max)
    @ realms -> [list, of, realms]

    Methods used to validate input parameters. These checks usually hit either
    persistent or temporary storage such as databases or the filesystem. See
    each methods documentation for detailed usage.
    The following methods must be implemented:

    - validate_client
    - validate_request_token
    - validate_access_token
    - validate_nonce_and_timestamp
    - validate_redirect_uri
    - validate_requested_realm
    - validate_realm
    - validate_verifier

    Method used to retrieve sensitive information from storage.
    The following methods must be implemented:

    - get_client_secret
    - get_request_token_secret
    - get_access_token_secret
    - get_rsa_key

    To prevent timing attacks it is necessary to not exit early even if the
    client key or resource owner key is invalid. Instead dummy values should
    be used during the remaining verification process. It is very important
    that the dummy client and token are valid input parameters to the methods
    get_client_secret, get_rsa_key and get_(access/request)_token_secret and
    that the running time of those methods when given a dummy value remain
    equivalent to the running time when given a valid client/resource owner.
    The following properties must be implemented:

    @ dummy_client
    @ dummy_request_token
    @ dummy_access_token

    .. _`whitelisting or blacklisting`: http://www.schneier.com/blog/archives/2011/01/whitelisting_vs.html
    """

    def __init__(self):
        pass

    @property
    def allowed_signature_methods(self):
        return SIGNATURE_METHODS

    @property
    def safe_characters(self):
        return set(utils.UNICODE_ASCII_CHARACTER_SET)

    @property
    def client_key_length(self):
        return 20, 30

    @property
    def request_token_length(self):
        return 20, 30

    @property
    def access_token_length(self):
        return 20, 30

    @property
    def timestamp_lifetime(self):
        return 600

    @property
    def nonce_length(self):
        return 20, 30

    @property
    def verifier_length(self):
        return 20, 30

    @property
    def realms(self):
        return []

    @property
    def enforce_ssl(self):
        return True

    def check_client_key(self, client_key):
        """Check that the client key only contains safe characters
        and is no shorter than lower and no longer than upper.
        """
        lower, upper = self.client_key_length
        return (set(client_key) <= self.safe_characters and
                lower <= len(client_key) <= upper)

    def check_request_token(self, request_token):
        """Checks that the request token contains only safe characters
        and is no shorter than lower and no longer than upper.
        """
        lower, upper = self.request_token_length
        return (set(request_token) <= self.safe_characters and
                lower <= len(request_token) <= upper)

    def check_access_token(self, request_token):
        """Checks that the token contains only safe characters
        and is no shorter than lower and no longer than upper.
        """
        lower, upper = self.access_token_length
        return (set(request_token) <= self.safe_characters and
                lower <= len(request_token) <= upper)

    def check_nonce(self, nonce):
        """Checks that the nonce only contains only safe characters
        and is no shorter than lower and no longer than upper.
        """
        lower, upper = self.nonce_length
        return (set(nonce) <= self.safe_characters and
                lower <= len(nonce) <= upper)

    def check_verifier(self, verifier):
        """Checks that the verifier contains only safe characters
        and is no shorter than lower and no longer than upper.
        """
        lower, upper = self.verifier_length
        return (set(verifier) <= self.safe_characters and
                lower <= len(verifier) <= upper)

    def check_realm(self, realm):
        """Check that the realm is one of a set allowed realms.
        """
        return realm in self.realms

    def get_client_secret(self, client_key):
        """Retrieves the client secret associated with the client key.

        This method must allow the use of a dummy client_key value.
        Fetching the secret using the dummy key must take the same amount of
        time as fetching a secret for a valid client.

        Note that the returned key must be in plaintext.
        """
        raise NotImplementedError("Subclasses must implement this function.")

    @property
    def dummy_client(self):
        """Dummy client used when an invalid client key is supplied.

        The dummy client should be associated with either a client secret,
        a rsa key or both depending on which signature methods are supported.
        Providers should make sure that

        get_client_secret(dummy_client)
        get_rsa_key(dummy_client)

        return a valid secret or key for the dummy client.
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def get_request_token_secret(self, client_key, request_token):
        """Retrieves the shared secret associated with the request token.

        This method must allow the use of a dummy values and the running time
        must be roughly equivalent to that of the running time of valid values.

        Note that the returned key must be in plaintext.
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def get_access_token_secret(self, client_key, access_token):
        """Retrieves the shared secret associated with the access token.

        This method must allow the use of a dummy values and the running time
        must be roughly equivalent to that of the running time of valid values.

        Note that the returned key must be in plaintext.
        """
        raise NotImplementedError("Subclasses must implement this function.")

    @property
    def dummy_request_token(self):
        """Dummy request token used when an invalid token was supplied.

        The dummy request token should be associated with a request token
        secret such that get_request_token_secret(.., dummy_request_token)
        returns a valid secret.
        """
        raise NotImplementedError("Subclasses must implement this function.")

    @property
    def dummy_access_token(self):
        """Dummy access token used when an invalid token was supplied.

        The dummy access token should be associated with an access token
        secret such that get_access_token_secret(.., dummy_access_token)
        returns a valid secret.
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def get_rsa_key(self, client_key):
        """Retrieves a previously stored client provided RSA key.

        This method must allow the use of a dummy client_key value. Fetching
        the rsa key using the dummy key must take the same aount of time
        as fetching a key for a valid client.

        Note that the key must be returned in plaintext.
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def get_signature_type_and_params(self, request):
        """Extracts parameters from query, headers and body. Signature type
        is set to the source in which parameters were found.
        """
        header_params = signature.collect_parameters(headers=request.headers,
                exclude_oauth_signature=False)
        body_params = signature.collect_parameters(body=request.body,
                exclude_oauth_signature=False)
        query_params = signature.collect_parameters(uri_query=request.uri_query,
                exclude_oauth_signature=False)

        params = []
        params.extend(header_params)
        params.extend(body_params)
        params.extend(query_params)
        signature_types_with_oauth_params = filter(lambda s: s[2], (
            (SIGNATURE_TYPE_AUTH_HEADER, params,
                utils.filter_oauth_params(header_params)),
            (SIGNATURE_TYPE_BODY, params,
                utils.filter_oauth_params(body_params)),
            (SIGNATURE_TYPE_QUERY, params,
                utils.filter_oauth_params(query_params))
        ))

        if len(signature_types_with_oauth_params) > 1:
            raise ValueError('oauth_ params must come from only 1 signature type but were found in %s' % ', '.join(
                [s[0] for s in signature_types_with_oauth_params]))
        try:
            signature_type, params, oauth_params = signature_types_with_oauth_params[0]
        except IndexError:
            raise ValueError('oauth_ params are missing. Could not determine signature type.')

        return signature_type, params, oauth_params

    def validate_client_key(self, client_key):
        """Validates that supplied client key is a registered and valid client.

        Note that if the dummy client is supplied it should validate in same
        or nearly the same amount of time as a valid one.

        Bad:

            if client_key == self.dummy_client:
                return False
            else:
                return storage.has_client(client_key)

        Good:

            return storage.has_client(client_key) and client_key != self.dummy_client
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def validate_request_token(self, client_key, request_token):
        """Validates that supplied request token is registered and valid.

        Note that if the dummy request_token is supplied it should validate in
        the same nearly the same amount of time as a valid one.

        Bad:

            if request_token == self.dummy_request_token:
                return False
            else:
                return storage.has_request_token(request_token)

        Good:

            return (storage.has_request_token(request_token) and
                    request_token != self.dummy_request_token)
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def validate_access_token(self, client_key, access_token):
        """Validates that supplied access token is registered and valid.

        Note that if the dummy access token is supplied it should validate in
        the same or nearly the same amount of time as a valid one.

        Bad:

            if access_token == self.dummy_access_token:
                return False
            else:
                return storage.has_access_token(access_token)

        Good:

            return (storage.has_access_token(access_token) and
                    access_token != self.dummy_access_token)
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
        request_token=None, access_token=None):
        """Validates that the nonce has not been used before.

        Per `Section 3.3`_ of the spec.

        "A nonce is a random string, uniquely generated by the client to allow
        the server to verify that a request has never been made before and
        helps prevent replay attacks when requests are made over a non-secure
        channel.  The nonce value MUST be unique across all requests with the
        same timestamp, client credentials, and token combinations."

        .. _`Section 3.3`: http://tools.ietf.org/html/rfc5849#section-3.3

        """
        raise NotImplementedError("Subclasses must implement this function.")

    def validate_redirect_uri(self, client_key, redirect_uri):
        """Validates the client supplied redirection URI.

        It is highly recommended that OAuth providers require their clients
        to register all redirection URIs prior to using them in requests and
        register them as absolute URIs. See `CWE-601`_ for more information
        about open redirection attacks.

        By requiring registration of all redirection URIs it should be
        straightforward for the provider to verify whether the supplied
        redirect_uri is valid or not.

        .. _`CWE-601`: http://cwe.mitre.org/top25/index.html#CWE-601
        """
        raise NotImplementedError("Subclasses must implement this function.")


    def validate_requested_realm(self, client_key, realm):
        """Validates that the client may request access to the realm.

        This method is invoked when obtaining a request token and should
        tie a realm to the request token and after user authorization
        this realm restriction should transfer to the access token.
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def validate_realm(self, client_key, access_token, uri=None,
            required_realm=None):
        """Validates access to the request realm.

        How providers choose to use the realm parameter is outside the OAuth
        specification but it is commonly used to restrict access to a subset
        of protected resources such as "photos".

        required_realm is a convenience parameter which can be used to provide
        a per view method pre-defined list of allowed realms.
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def validate_verifier(self, client_key, request_token, verifier):
        """Validates a verification code.

        OAuth providers issue a verification code to clients after the
        resource owner authorizes access. This code is used by the client to
        obtain token credentials and the provider must verify that the
        verifier is valid and associated with the client as well as the
        resource owner.
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def verify_request(self, uri, http_method=u'GET', body=None,
            headers=None, require_resource_owner=True, require_verifier=False,
            require_realm=False, required_realm=None):
        """Verifies a request ensuring that the following is true:

        Per `section 3.2`_ of the spec.

        - all mandated OAuth parameters are supplied
        - parameters are only supplied in one source which may be the URI
          query, the Authorization header or the body
        - all parameters are checked and validated, see comments and the
          methods and properties of this class for further details.
        - the supplied signature is verified against a recalculated one

        A ValueError will be raised if any parameter is missing,
        supplied twice or invalid. A HTTP 400 Response should be returned
        upon catching an exception.

        A HTTP 401 Response should be returned if verify_request returns False.

        `Timing attacks`_ are prevented through the use of dummy credentials to
        create near constant time verification even if an invalid credential
        is used. Early exit on invalid credentials would enable attackers
        to perform `enumeration attacks`_. Near constant time string comparison
        is used to prevent secret key guessing. Note that timing attacks can
        only be prevented through near constant time execution, not by adding
        a random delay which would only require more samples to be gathered.

        .. _`section 3.2`: http://tools.ietf.org/html/rfc5849#section-3.2
        .. _`Timing attacks`: http://rdist.root.org/2010/07/19/exploiting-remote-timing-attacks/
        .. _`enumeration attacks`: http://www.sans.edu/research/security-laboratory/article/attacks-browsing
        """
        # Only include body data from x-www-form-urlencoded requests
        headers = headers or {}
        if (u"Content-Type" in headers and
                headers[u"Content-Type"] == CONTENT_TYPE_FORM_URLENCODED):
            request = Request(uri, http_method, body, headers)
        else:
            request = Request(uri, http_method, u'', headers)

        if self.enforce_ssl and not request.uri.lower().startswith("https://"):
            raise ValueError("Insecure transport, only HTTPS is allowed.")

        signature_type, params, oauth_params = self.get_signature_type_and_params(request)

        # The server SHOULD return a 400 (Bad Request) status code when
        # receiving a request with duplicated protocol parameters.
        if len(dict(oauth_params)) != len(oauth_params):
            raise ValueError("Duplicate OAuth entries.")

        oauth_params = dict(oauth_params)
        request_signature = oauth_params.get(u'oauth_signature')
        client_key = oauth_params.get(u'oauth_consumer_key')
        resource_owner_key = oauth_params.get(u'oauth_token')
        nonce = oauth_params.get(u'oauth_nonce')
        timestamp = oauth_params.get(u'oauth_timestamp')
        callback_uri = oauth_params.get(u'oauth_callback')
        verifier = oauth_params.get(u'oauth_verifier')
        signature_method = oauth_params.get(u'oauth_signature_method')
        realm = dict(params).get(u'realm')

        # The server SHOULD return a 400 (Bad Request) status code when
        # receiving a request with missing parameters.
        if not all((request_signature, client_key, nonce,
                    timestamp, signature_method)):
            raise ValueError("Missing OAuth parameters.")

        # OAuth does not mandate a particular signature method, as each
        # implementation can have its own unique requirements.  Servers are
        # free to implement and document their own custom methods.
        # Recommending any particular method is beyond the scope of this
        # specification.  Implementers should review the Security
        # Considerations section (`Section 4`_) before deciding on which
        # method to support.
        # .. _`Section 4`: http://tools.ietf.org/html/rfc5849#section-4
        if not signature_method in self.allowed_signature_methods:
            raise ValueError("Invalid signature method.")

        # Servers receiving an authenticated request MUST validate it by:
        #   If the "oauth_version" parameter is present, ensuring its value is
        #   "1.0".
        if u'oauth_version' in oauth_params and oauth_params[u'oauth_version'] != u'1.0':
            raise ValueError("Invalid OAuth version.")

        # The timestamp value MUST be a positive integer. Unless otherwise
        # specified by the server's documentation, the timestamp is expressed
        # in the number of seconds since January 1, 1970 00:00:00 GMT.
        if len(timestamp) != 10:
            raise ValueError("Invalid timestamp size")
        try:
            ts = int(timestamp)

        except ValueError:
            raise ValueError("Timestamp must be an integer")

        else:
            # To avoid the need to retain an infinite number of nonce values for
            # future checks, servers MAY choose to restrict the time period after
            # which a request with an old timestamp is rejected.
            if time.time() - ts > self.timestamp_lifetime:
                raise ValueError("Request too old, over 10 minutes.")

        # Provider specific validation of parameters, used to enforce
        # restrictions such as character set and length.
        if not self.check_client_key(client_key):
            raise ValueError("Invalid client key.")

        if not resource_owner_key and require_resource_owner:
            raise ValueError("Missing resource owner.")

        if (require_resource_owner and not require_verifier and
            not self.check_access_token(resource_owner_key)):
            raise ValueError("Invalid resource owner key.")

        if (require_resource_owner and require_verifier and
            not self.check_request_token(resource_owner_key)):
            raise ValueError("Invalid resource owner key.")

        if not self.check_nonce(nonce):
            raise ValueError("Invalid nonce.")

        if realm and not self.check_realm(realm):
            raise ValueError("Invalid realm. Allowed are %s" % self.realms)

        if not verifier and require_verifier:
            raise ValueError("Missing verifier.")

        if require_verifier and not self.check_verifier(verifier):
            raise ValueError("Invalid verifier.")

        # Servers receiving an authenticated request MUST validate it by:
        #   If using the "HMAC-SHA1" or "RSA-SHA1" signature methods, ensuring
        #   that the combination of nonce/timestamp/token (if present)
        #   received from the client has not been used before in a previous
        #   request (the server MAY reject requests with stale timestamps as
        #   described in `Section 3.3`_).
        # .._`Section 3.3`: http://tools.ietf.org/html/rfc5849#section-3.3
        #
        # We check this before validating client and resource owner for
        # increased security and performance, both gained by doing less work.
        if require_verifier:
            token = {"request_token": resource_owner_key}
        else:
            token = {"access_token": resource_owner_key}
        if not self.validate_timestamp_and_nonce(client_key, timestamp,
                nonce, **token):
                return False

        # The server SHOULD return a 401 (Unauthorized) status code when
        # receiving a request with invalid client credentials.
        # Note: This is postponed in order to avoid timing attacks, instead
        # a dummy client is assigned and used to maintain near constant
        # time request verification.
        #
        # Note that early exit would enable client enumeration
        valid_client = self.validate_client_key(client_key)
        if not valid_client:
            client_key = self.dummy_client

        # Ensure a valid redirection uri is used
        valid_redirect = self.validate_redirect_uri(client_key, callback_uri)

        # The server SHOULD return a 401 (Unauthorized) status code when
        # receiving a request with invalid or expired token.
        # Note: This is postponed in order to avoid timing attacks, instead
        # a dummy token is assigned and used to maintain near constant
        # time request verification.
        #
        # Note that early exit would enable resource owner enumeration
        if resource_owner_key:
            if require_verifier:
                valid_resource_owner = self.validate_request_token(
                    client_key, resource_owner_key)
            else:
                valid_resource_owner = self.validate_access_token(
                    client_key, resource_owner_key)
            if not valid_resource_owner:
                resource_owner_key = self.dummy_resource_owner
        else:
            valid_resource_owner = True

        # Note that `realm`_ is only used in authorization headers and how
        # it should be interepreted is not included in the OAuth spec.
        # However they could be seen as a scope or realm to which the
        # client has access and as such every client should be checked
        # to ensure it is authorized access to that scope or realm.
        # .. _`realm`: http://tools.ietf.org/html/rfc2617#section-1.2
        #
        # Note that early exit would enable client realm access enumeration.
        #
        # The require_realm indicates this is the first step in the OAuth
        # workflow where a client requests access to a specific realm.
        #
        # Clients obtaining an access token will not supply a realm and it will
        # not be checked. Instead the previously requested realm should be
        # transferred from the request token to the access token.
        #
        # Access to protected resources will always validate the realm but note
        # that the realm is now tied to the access token and not provided by
        # the client.
        if require_realm and not resource_owner_key:
            valid_realm = self.validate_requested_realm(client_key, realm)
        elif require_verifier:
            valid_realm = True
        else:
            valid_realm = self.validate_realm(client_key, resource_owner_key,
                    uri=request.uri, required_realm=required_realm)

        # The server MUST verify (Section 3.2) the validity of the request,
        # ensure that the resource owner has authorized the provisioning of
        # token credentials to the client, and ensure that the temporary
        # credentials have not expired or been used before.  The server MUST
        # also verify the verification code received from the client.
        # .. _`Section 3.2`: http://tools.ietf.org/html/rfc5849#section-3.2
        #
        # Note that early exit would enable resource owner authorization
        # verifier enumertion.
        if verifier:
            valid_verifier = self.validate_verifier(client_key,
                resource_owner_key, verifier)
        else:
            valid_verifier = True

        # Parameters to Client depend on signature method which may vary
        # for each request. Note that HMAC-SHA1 and PLAINTEXT share parameters

        request.params = filter(lambda x: x[0] != "oauth_signature", params)
        request.signature = request_signature

        # ---- RSA Signature verification ----
        if signature_method == SIGNATURE_RSA:
            # The server verifies the signature per `[RFC3447] section 8.2.2`_
            # .. _`[RFC3447] section 8.2.2`: http://tools.ietf.org/html/rfc3447#section-8.2.1
            rsa_key = self.get_rsa_key(client_key)
            valid_signature = signature.verify_rsa_sha1(request, rsa_key)

        # ---- HMAC or Plaintext Signature verification ----
        else:
            # Servers receiving an authenticated request MUST validate it by:
            #   Recalculating the request signature independently as described in
            #   `Section 3.4`_ and comparing it to the value received from the
            #   client via the "oauth_signature" parameter.
            # .. _`Section 3.4`: http://tools.ietf.org/html/rfc5849#section-3.4
            client_secret = self.get_client_secret(client_key)
            if require_verifier:
                resource_owner_secret = self.get_request_token_secret(
                    client_key, resource_owner_key)
            else:
                resource_owner_secret = self.get_access_token_secret(
                    client_key, resource_owner_key)

            if signature_method == SIGNATURE_HMAC:
                valid_signature = signature.verify_hmac_sha1(request,
                    client_secret, resource_owner_secret)
            else:
                valid_signature = signature.verify_plaintext(request,
                    client_secret, resource_owner_secret)

        # We delay checking validity until the very end, using dummy values for
        # calculations and fetching secrets/keys to ensure the flow of every
        # request remains almost identical regardless of whether valid values
        # have been supplied. This ensures near constant time execution and
        # prevents malicious users from guessing sensitive information
        v = all((valid_client, valid_resource_owner, valid_realm,
                    valid_redirect, valid_verifier, valid_signature))
        logger = logging.getLogger("oauthlib")
        if not v:
            logger.info("[Failure] OAuthLib request verification failed.")
            logger.info("Valid client:\t%s" % valid_client)
            logger.info("Valid token:\t%s\t(Required: %s" % (valid_resource_owner, require_resource_owner))
            logger.info("Valid realm:\t%s\t(Required: %s)" % (valid_realm, require_realm))
            logger.info("Valid callback:\t%s" % valid_redirect)
            logger.info("Valid verifier:\t%s\t(Required: %s)" % (valid_verifier, require_verifier))
            logger.info("Valid signature:\t%s" % valid_signature)
        return v
