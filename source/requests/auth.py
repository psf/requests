# -*- coding: utf-8 -*-

"""
requests.auth
~~~~~~~~~~~~~

This module contains the authentication handlers for Requests.
"""

import os
import re
import time
import hashlib
import logging

from base64 import b64encode

from .compat import urlparse, str
from .utils import parse_dict_header

try:
    from ._oauth import (Client, SIGNATURE_HMAC, SIGNATURE_TYPE_AUTH_HEADER, extract_params)

except (ImportError, SyntaxError):
    SIGNATURE_HMAC = None
    SIGNATURE_TYPE_AUTH_HEADER = None

try:
    import kerberos as k
except ImportError as exc:
    k = None

log = logging.getLogger(__name__)

CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'
CONTENT_TYPE_MULTI_PART = 'multipart/form-data'


def _basic_auth_str(username, password):
    """Returns a Basic Auth string."""

    return 'Basic ' + b64encode(('%s:%s' % (username, password)).encode('latin1')).strip().decode('latin1')


class AuthBase(object):
    """Base class that all auth implementations derive from"""

    def __call__(self, r):
        raise NotImplementedError('Auth hooks must be callable.')


class OAuth1(AuthBase):
    """Signs the request using OAuth 1 (RFC5849)"""
    def __init__(self, client_key,
            client_secret=None,
            resource_owner_key=None,
            resource_owner_secret=None,
            callback_uri=None,
            signature_method=SIGNATURE_HMAC,
            signature_type=SIGNATURE_TYPE_AUTH_HEADER,
            rsa_key=None, verifier=None):

        try:
            signature_type = signature_type.upper()
        except AttributeError:
            pass

        self.client = Client(client_key, client_secret, resource_owner_key,
            resource_owner_secret, callback_uri, signature_method,
            signature_type, rsa_key, verifier)

    def __call__(self, r):
        """Add OAuth parameters to the request.

        Parameters may be included from the body if the content-type is
        urlencoded, if no content type is set an educated guess is made.
        """
        # split(";") because Content-Type may be "multipart/form-data; boundary=xxxxx"
        contenttype = r.headers.get('Content-Type', '').split(";")[0].lower()
        # extract_params will not give params unless the body is a properly
        # formatted string, a dictionary or a list of 2-tuples.
        decoded_body = extract_params(r.data)

        # extract_params can only check the present r.data and does not know
        # of r.files, thus an extra check is performed. We know that
        # if files are present the request will not have
        # Content-type: x-www-form-urlencoded. We guess it will have
        # a mimetype of multipart/form-data and if this is not the case
        # we assume the correct header will be set later.
        _oauth_signed = True
        if r.files and contenttype == CONTENT_TYPE_MULTI_PART:
            # Omit body data in the signing and since it will always
            # be empty (cant add paras to body if multipart) and we wish
            # to preserve body.
            r.url, r.headers, _ = self.client.sign(
                unicode(r.full_url), unicode(r.method), None, r.headers)
        elif decoded_body is not None and contenttype in (CONTENT_TYPE_FORM_URLENCODED, ''):
            # Normal signing
            if not contenttype:
                r.headers['Content-Type'] = CONTENT_TYPE_FORM_URLENCODED
            r.url, r.headers, r.data = self.client.sign(
                unicode(r.full_url), unicode(r.method), r.data, r.headers)
        else:
            _oauth_signed = False
        if _oauth_signed:
            # Both flows add params to the URL by using r.full_url,
            # so this prevents adding it again later
            r.params = {}

            # Having the authorization header, key or value, in unicode will
            # result in UnicodeDecodeErrors when the request is concatenated
            # by httplib. This can easily be seen when attaching files.
            # Note that simply encoding the value is not enough since Python
            # saves the type of first key set. Thus we remove and re-add.
            # >>> d = {u'a':u'foo'}
            # >>> d['a'] = 'foo'
            # >>> d
            # { u'a' : 'foo' }
            u_header = unicode('Authorization')
            if u_header in r.headers:
                auth_header = r.headers[u_header].encode('utf-8')
                del r.headers[u_header]
                r.headers['Authorization'] = auth_header

        return r


class HTTPBasicAuth(AuthBase):
    """Attaches HTTP Basic Authentication to the given Request object."""
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __call__(self, r):
        r.headers['Authorization'] = _basic_auth_str(self.username, self.password)
        return r


class HTTPProxyAuth(HTTPBasicAuth):
    """Attaches HTTP Proxy Authenetication to a given Request object."""
    def __call__(self, r):
        r.headers['Proxy-Authorization'] = _basic_auth_str(self.username, self.password)
        return r


class HTTPDigestAuth(AuthBase):
    """Attaches HTTP Digest Authentication to the given Request object."""
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.last_nonce = ''
        self.nonce_count = 0
        self.chal = {}

    def build_digest_header(self, method, url):

        realm = self.chal['realm']
        nonce = self.chal['nonce']
        qop = self.chal.get('qop')
        algorithm = self.chal.get('algorithm', 'MD5')
        opaque = self.chal.get('opaque', None)

        algorithm = algorithm.upper()
        # lambdas assume digest modules are imported at the top level
        if algorithm == 'MD5':
            def md5_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.md5(x).hexdigest()
            hash_utf8 = md5_utf8
        elif algorithm == 'SHA':
            def sha_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha1(x).hexdigest()
            hash_utf8 = sha_utf8
        # XXX MD5-sess
        KD = lambda s, d: hash_utf8("%s:%s" % (s, d))

        if hash_utf8 is None:
            return None

        # XXX not implemented yet
        entdig = None
        p_parsed = urlparse(url)
        path = p_parsed.path
        if p_parsed.query:
            path += '?' + p_parsed.query

        A1 = '%s:%s:%s' % (self.username, realm, self.password)
        A2 = '%s:%s' % (method, path)

        if qop == 'auth':
            if nonce == self.last_nonce:
                self.nonce_count += 1
            else:
                self.nonce_count = 1

            ncvalue = '%08x' % self.nonce_count
            s = str(self.nonce_count).encode('utf-8')
            s += nonce.encode('utf-8')
            s += time.ctime().encode('utf-8')
            s += os.urandom(8)

            cnonce = (hashlib.sha1(s).hexdigest()[:16])
            noncebit = "%s:%s:%s:%s:%s" % (nonce, ncvalue, cnonce, qop, hash_utf8(A2))
            respdig = KD(hash_utf8(A1), noncebit)
        elif qop is None:
            respdig = KD(hash_utf8(A1), "%s:%s" % (nonce, hash_utf8(A2)))
        else:
            # XXX handle auth-int.
            return None

        self.last_nonce = nonce

        # XXX should the partial digests be encoded too?
        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
           'response="%s"' % (self.username, realm, nonce, path, respdig)
        if opaque:
            base += ', opaque="%s"' % opaque
        if entdig:
            base += ', digest="%s"' % entdig
            base += ', algorithm="%s"' % algorithm
        if qop:
            base += ', qop=auth, nc=%s, cnonce="%s"' % (ncvalue, cnonce)

        return 'Digest %s' % (base)

    def handle_401(self, r):
        """Takes the given response and tries digest-auth, if needed."""

        num_401_calls = r.request.hooks['response'].count(self.handle_401)

        s_auth = r.headers.get('www-authenticate', '')

        if 'digest' in s_auth.lower() and num_401_calls < 2:

            self.chal = parse_dict_header(s_auth.replace('Digest ', ''))

            # Consume content and release the original connection
            # to allow our new request to reuse the same one.
            r.content
            r.raw.release_conn()

            r.request.headers['Authorization'] = self.build_digest_header(r.request.method, r.request.url)
            r.request.send(anyway=True)
            _r = r.request.response
            _r.history.append(r)

            return _r

        return r

    def __call__(self, r):
        # If we have a saved nonce, skip the 401
        if self.last_nonce:
            r.headers['Authorization'] = self.build_digest_header(r.method, r.url)
        r.register_hook('response', self.handle_401)
        return r


def _negotiate_value(r):
    """Extracts the gssapi authentication token from the appropriate header"""

    authreq = r.headers.get('www-authenticate', None)

    if authreq:
        rx = re.compile('(?:.*,)*\s*Negotiate\s*([^,]*),?', re.I)
        mo = rx.search(authreq)
        if mo:
            return mo.group(1)

    return None


class HTTPKerberosAuth(AuthBase):
    """Attaches HTTP GSSAPI/Kerberos Authentication to the given Request object."""
    def __init__(self, require_mutual_auth=True):
        if k is None:
            raise Exception("Kerberos libraries unavailable")
        self.context = None
        self.require_mutual_auth = require_mutual_auth

    def generate_request_header(self, r):
        """Generates the gssapi authentication token with kerberos"""

        host = urlparse(r.url).netloc
        tail, _, head = host.rpartition(':')
        domain = tail if tail else head

        result, self.context = k.authGSSClientInit("HTTP@%s" % domain)

        if result < 1:
            raise Exception("authGSSClientInit failed")

        result = k.authGSSClientStep(self.context, _negotiate_value(r))

        if result < 0:
            raise Exception("authGSSClientStep failed")

        response = k.authGSSClientResponse(self.context)

        return "Negotiate %s" % response

    def authenticate_user(self, r):
        """Handles user authentication with gssapi/kerberos"""

        auth_header = self.generate_request_header(r)
        log.debug("authenticate_user(): Authorization header: %s" % auth_header)
        r.request.headers['Authorization'] = auth_header
        r.request.send(anyway=True)
        _r = r.request.response
        _r.history.append(r)
        log.debug("authenticate_user(): returning %s" % _r)
        return _r

    def handle_401(self, r):
        """Handles 401's, attempts to use gssapi/kerberos authentication"""

        log.debug("handle_401(): Handling: 401")
        if _negotiate_value(r) is not None:
            _r = self.authenticate_user(r)
            log.debug("handle_401(): returning %s" % _r)
            return _r
        else:
            log.debug("handle_401(): Kerberos is not supported")
            log.debug("handle_401(): returning %s" % r)
            return r

    def handle_other(self, r):
        """Handles all responses with the exception of 401s.

        This is necessary so that we can authenticate responses if requested"""

        log.debug("handle_other(): Handling: %d" % r.status_code)
        self.deregister(r)
        if self.require_mutual_auth:
            if _negotiate_value(r) is not None:
                log.debug("handle_other(): Authenticating the server")
                _r = self.authenticate_server(r)
                log.debug("handle_other(): returning %s" % _r)
                return _r
            else:
                log.error("handle_other(): Mutual authentication failed")
                raise Exception("Mutual authentication failed")
        else:
            log.debug("handle_other(): returning %s" % r)
            return r

    def authenticate_server(self, r):
        """Uses GSSAPI to authenticate the server"""

        log.debug("authenticate_server(): Authenticate header: %s" % _negotiate_value(r))
        result = k.authGSSClientStep(self.context, _negotiate_value(r))
        if  result < 1:
            raise Exception("authGSSClientStep failed")
        _r = r.request.response
        log.debug("authenticate_server(): returning %s" % _r)
        return _r

    def handle_response(self, r):
        """Takes the given response and tries kerberos-auth, as needed."""

        if r.status_code == 401:
            _r = self.handle_401(r)
            log.debug("handle_response returning %s" % _r)
            return _r
        else:
            _r = self.handle_other(r)
            log.debug("handle_response returning %s" % _r)
            return _r

        log.debug("handle_response returning %s" % r)
        return r

    def deregister(self, r):
        """Deregisters the response handler"""
        r.request.deregister_hook('response', self.handle_response)

    def __call__(self, r):
        r.register_hook('response', self.handle_response)
        return r
