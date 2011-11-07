# -*- coding: utf-8 -*-

"""
requests.auth
~~~~~~~~~~~~~

This module contains the authentication handlers for Requests.
"""

import time
import hashlib

from base64 import b64encode
from urlparse import urlparse

from .utils import randombytes, parse_dict_header


def http_basic(r, username, password):
    """Attaches HTTP Basic Authentication to the given Request object.
    Arguments should be considered non-positional.

    """
    username = str(username)
    password = str(password)

    auth_s = b64encode('%s:%s' % (username, password))
    r.headers['Authorization'] = ('Basic %s' % auth_s)

    return r


def http_digest(r, username, password):
    """Attaches HTTP Digest Authentication to the given Request object.
    Arguments should be considered non-positional.
    """

    def handle_401(r):
        """Takes the given response and tries digest-auth, if needed."""

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
                H = lambda x: hashlib.md5(x).hexdigest()
            elif algorithm == 'SHA':
                H = lambda x: hashlib.sha1(x).hexdigest()
            # XXX MD5-sess
            KD = lambda s, d: H("%s:%s" % (s, d))

            if H is None:
                return None

            # XXX not implemented yet
            entdig = None
            p_parsed = urlparse(r.request.url)
            path = p_parsed.path + p_parsed.query

            A1 = "%s:%s:%s" % (username, realm, password)
            A2 = "%s:%s" % (r.request.method, path)

            if qop == 'auth':
                if nonce == last_nonce:
                    nonce_count += 1
                else:
                    nonce_count = 1
                    last_nonce = nonce

                ncvalue = '%08x' % nonce_count
                cnonce = (hashlib.sha1("%s:%s:%s:%s" % (
                    nonce_count, nonce, time.ctime(), randombytes(8)))
                    .hexdigest()[:16]
                )
                noncebit = "%s:%s:%s:%s:%s" % (nonce, ncvalue, cnonce, qop, H(A2))
                respdig = KD(H(A1), noncebit)
            elif qop is None:
                respdig = KD(H(A1), "%s:%s" % (nonce, H(A2)))
            else:
                # XXX handle auth-int.
                return None

            # XXX should the partial digests be encoded too?
            base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
                   'response="%s"' % (username, realm, nonce, path, respdig)
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

    r.hooks['response'] = handle_401
    return r


def dispatch(t):
    """Given an auth tuple, return an expanded version."""

    if not t:
        return t
    else:
        t = list(t)

    # Make sure they're passing in something.
    assert len(t) >= 2

    # If only two items are passed in, assume HTTPBasic.
    if (len(t) == 2):
        t.insert(0, 'basic')

    # Allow built-in string referenced auths.
    if isinstance(t[0], basestring):
        if t[0] in ('basic', 'forced_basic'):
            t[0] = http_basic
        elif t[0] in ('digest',):
            t[0] = http_digest

    # Return a custom callable.
    return (t[0], tuple(t[1:]))


