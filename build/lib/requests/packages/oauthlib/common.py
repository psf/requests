# -*- coding: utf-8 -*-
from __future__ import absolute_import

"""
oauthlib.common
~~~~~~~~~~~~~~

This module provides data structures and utilities common
to all implementations of OAuth.
"""

import random
import re
import string
import time
import urllib
import urlparse

UNICODE_ASCII_CHARACTER_SET = (string.ascii_letters.decode('ascii') +
    string.digits.decode('ascii'))

always_safe = (u'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
               u'abcdefghijklmnopqrstuvwxyz'
               u'0123456789' u'_.-')


def quote(s, safe=u'/'):
    encoded = s.encode("utf-8")
    quoted = urllib.quote(encoded, safe)
    return quoted.decode("utf-8")


def unquote(s):
    encoded = s.encode("utf-8")
    unquoted = urllib.unquote(encoded)
    return unquoted.decode("utf-8")


def urlencode(params):
    utf8_params = encode_params_utf8(params)
    urlencoded = urllib.urlencode(utf8_params)
    return urlencoded.decode("utf-8")


def encode_params_utf8(params):
    """Ensures that all parameters in a list of 2-element tuples are encoded to
    bytestrings using UTF-8
    """
    encoded = []
    for k, v in params:
        encoded.append((
            k.encode('utf-8') if isinstance(k, unicode) else k,
            v.encode('utf-8') if isinstance(v, unicode) else v))
    return encoded


def decode_params_utf8(params):
    """Ensures that all parameters in a list of 2-element tuples are decoded to
    unicode using UTF-8.
    """
    decoded = []
    for k, v in params:
        decoded.append((
            k.decode('utf-8') if isinstance(k, str) else k,
            v.decode('utf-8') if isinstance(v, str) else v))
    return decoded


urlencoded = set(always_safe) | set(u'=&;%+~')


def urldecode(query):
    """Decode a query string in x-www-form-urlencoded format into a sequence
    of two-element tuples.

    Unlike urlparse.parse_qsl(..., strict_parsing=True) urldecode will enforce
    correct formatting of the query string by validation. If validation fails
    a ValueError will be raised. urllib.parse_qsl will only raise errors if
    any of name-value pairs omits the equals sign.
    """
    # Check if query contains invalid characters
    if query and not set(query) <= urlencoded:
        raise ValueError('Invalid characters in query string.')

    # Check for correctly hex encoded values using a regular expression
    # All encoded values begin with % followed by two hex characters
    # correct = %00, %A0, %0A, %FF
    # invalid = %G0, %5H, %PO
    invalid_hex = u'%[^0-9A-Fa-f]|%[0-9A-Fa-f][^0-9A-Fa-f]'
    if len(re.findall(invalid_hex, query)):
        raise ValueError('Invalid hex encoding in query string.')

    query = query.decode('utf-8') if isinstance(query, str) else query
    # We want to allow queries such as "c2" whereas urlparse.parse_qsl
    # with the strict_parsing flag will not.
    params = urlparse.parse_qsl(query, keep_blank_values=True)

    # unicode all the things
    return decode_params_utf8(params)


def extract_params(raw):
    """Extract parameters and return them as a list of 2-tuples.

    Will successfully extract parameters from urlencoded query strings,
    dicts, or lists of 2-tuples. Empty strings/dicts/lists will return an
    empty list of parameters. Any other input will result in a return
    value of None.
    """
    if isinstance(raw, basestring):
        try:
            params = urldecode(raw)
        except ValueError:
            params = None
    elif hasattr(raw, '__iter__'):
        try:
            dict(raw)
        except ValueError:
            params = None
        except TypeError:
            params = None
        else:
            params = list(raw.items() if isinstance(raw, dict) else raw)
            params = decode_params_utf8(params)
    else:
        params = None

    return params


def generate_nonce():
    """Generate pseudorandom nonce that is unlikely to repeat.

    Per `section 3.3`_ of the OAuth 1 RFC 5849 spec.
    Per `section 3.2.1`_ of the MAC Access Authentication spec.

    A random 64-bit number is appended to the epoch timestamp for both
    randomness and to decrease the likelihood of collisions.

    .. _`section 3.2.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01#section-3.2.1
    .. _`section 3.3`: http://tools.ietf.org/html/rfc5849#section-3.3
    """
    return unicode(unicode(random.getrandbits(64)) + generate_timestamp())


def generate_timestamp():
    """Get seconds since epoch (UTC).

    Per `section 3.3`_ of the OAuth 1 RFC 5849 spec.
    Per `section 3.2.1`_ of the MAC Access Authentication spec.

    .. _`section 3.2.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01#section-3.2.1
    .. _`section 3.3`: http://tools.ietf.org/html/rfc5849#section-3.3
    """
    return unicode(int(time.time()))


def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    """Generates a non-guessable OAuth token

    OAuth (1 and 2) does not specify the format of tokens except that they
    should be strings of random characters. Tokens should not be guessable
    and entropy when generating the random characters is important. Which is
    why SystemRandom is used instead of the default random.choice method.
    """
    rand = random.SystemRandom()
    return u''.join(rand.choice(chars) for x in range(length))


def add_params_to_qs(query, params):
    """Extend a query with a list of two-tuples."""
    queryparams = urlparse.parse_qsl(query, keep_blank_values=True)
    queryparams.extend(params)
    return urlencode(queryparams)


def add_params_to_uri(uri, params):
    """Add a list of two-tuples to the uri query components."""
    sch, net, path, par, query, fra = urlparse.urlparse(uri)
    query = add_params_to_qs(query, params)
    return urlparse.urlunparse((sch, net, path, par, query, fra))

def safe_string_equals(a, b):
    """ Near-constant time string comparison. 

    Used in order to avoid timing attacks on sensitive information such
    as secret keys during request verification (`rootLabs`_).

    .. _`rootLabs`: http://rdist.root.org/2010/01/07/timing-independent-array-comparison/
    
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

class Request(object):
    """A malleable representation of a signable HTTP request.

    Body argument may contain any data, but parameters will only be decoded if
    they are one of:

    * urlencoded query string
    * dict
    * list of 2-tuples

    Anything else will be treated as raw body data to be passed through
    unmolested.
    """

    def __init__(self, uri, http_method=u'GET', body=None, headers=None):
        self.uri = uri
        self.http_method = http_method
        self.headers = headers or {}
        self.body = body
        self.decoded_body = extract_params(body)
        self.oauth_params = []

    @property
    def uri_query(self):
        return urlparse.urlparse(self.uri).query

    @property
    def uri_query_params(self):
        return urlparse.parse_qsl(self.uri_query, keep_blank_values=True,
                                  strict_parsing=True)
