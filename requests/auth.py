# -*- coding: utf-8 -*-

"""
requests.auth
~~~~~~~~~~~~~

This module contains the authentication handlers for Requests.
"""

import os
import time
import hashlib

from base64 import b64encode

from .compat import urlparse, str
from .utils import parse_dict_header

try:
    from ._oauth import (Client, SIGNATURE_HMAC, SIGNATURE_TYPE_AUTH_HEADER, extract_params)

except (ImportError, SyntaxError):
    SIGNATURE_HMAC = None
    SIGNATURE_TYPE_AUTH_HEADER = None

CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'

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
        contenttype = r.headers.get('Content-Type', None)
        # extract_params will not give params unless the body is a properly
        # formatted string, a dictionary or a list of 2-tuples.
        decoded_body = extract_params(r.data)
        if contenttype == None and decoded_body != None:
            # extract_params can only check the present r.data and does not know
            # of r.files, thus an extra check is performed. We know that
            # if files are present the request will not have
            # Content-type: x-www-form-urlencoded. We guess it will have
            # a mimetype of multipart/form-encoded and if this is not the case
            # we assume the correct header will be set later.
            if r.files:
                # Omit body data in the signing and since it will always
                # be empty (cant add paras to body if multipart) and we wish
                # to preserve body.
                r.headers['Content-Type'] = 'multipart/form-encoded'
                r.url, r.headers, _ = self.client.sign(
                    unicode(r.full_url), unicode(r.method), None, r.headers)
            else:
                # Normal signing
                r.headers['Content-Type'] = 'application/x-www-form-urlencoded'
                r.url, r.headers, r.data = self.client.sign(
                    unicode(r.full_url), unicode(r.method), r.data, r.headers)

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

    def handle_401(self, r):
        """Takes the given response and tries digest-auth, if needed."""

        r.request.deregister_hook('response', self.handle_401)

        s_auth = r.headers.get('www-authenticate', '')

        if 'digest' in s_auth.lower():

            last_nonce = ''
            nonce_count = 0

            chal = parse_dict_header(s_auth.replace('Digest ', ''))

            realm = chal['realm']
            nonce = chal['nonce']
            qop = chal.get('qop')
            algorithm = chal.get('algorithm', 'MD5')
            opaque = chal.get('opaque', None)

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
            p_parsed = urlparse(r.request.url)
            path = p_parsed.path
            if p_parsed.query:
                path += '?' + p_parsed.query

            A1 = '%s:%s:%s' % (self.username, realm, self.password)
            A2 = '%s:%s' % (r.request.method, path)

            if qop == 'auth':
                if nonce == last_nonce:
                    nonce_count += 1
                else:
                    nonce_count = 1
                    last_nonce = nonce

                ncvalue = '%08x' % nonce_count
                s = str(nonce_count).encode('utf-8')
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

            r.request.headers['Authorization'] = 'Digest %s' % (base)
            r.request.send(anyway=True)
            _r = r.request.response
            _r.history.append(r)

            return _r

        return r

    def __call__(self, r):
        r.register_hook('response', self.handle_401)
        return r
