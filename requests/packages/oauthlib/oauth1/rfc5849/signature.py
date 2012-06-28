# -*- coding: utf-8 -*-
from __future__ import absolute_import
"""
oauthlib.oauth1.rfc5849.signature
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of `section 3.4`_ of the spec.

Terminology:
 * Client: software interfacing with an OAuth API
 * Server: the API provider
 * Resource Owner: the user who is granting authorization to the client

Steps for signing a request:

1. Collect parameters from the uri query, auth header, & body
2. Normalize those parameters
3. Normalize the uri
4. Pass the normalized uri, normalized parameters, and http method to
   construct the base string
5. Pass the base string and any keys needed to a signing function

.. _`section 3.4`: http://tools.ietf.org/html/rfc5849#section-3.4
"""
import binascii
import hashlib
import hmac
import urlparse
from . import utils
from oauthlib.common import extract_params, safe_string_equals


def construct_base_string(http_method, base_string_uri,
        normalized_encoded_request_parameters):
    """**String Construction**
    Per `section 3.4.1.1`_ of the spec.

    For example, the HTTP request::

        POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
        Host: example.com
        Content-Type: application/x-www-form-urlencoded
        Authorization: OAuth realm="Example",
            oauth_consumer_key="9djdj82h48djs9d2",
            oauth_token="kkk9d7dh3k39sjv7",
            oauth_signature_method="HMAC-SHA1",
            oauth_timestamp="137131201",
            oauth_nonce="7d8f3e4a",
            oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"

        c2&a3=2+q

    is represented by the following signature base string (line breaks
    are for display purposes only)::

        POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q
        %26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_
        key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m
        ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk
        9d7dh3k39sjv7

    .. _`section 3.4.1.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1.1
    """

    # The signature base string is constructed by concatenating together,
    # in order, the following HTTP request elements:

    # 1.  The HTTP request method in uppercase.  For example: "HEAD",
    #     "GET", "POST", etc.  If the request uses a custom HTTP method, it
    #     MUST be encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
    base_string = utils.escape(http_method.upper())

    # 2.  An "&" character (ASCII code 38).
    base_string += u'&'

    # 3.  The base string URI from `Section 3.4.1.2`_, after being encoded
    #     (`Section 3.6`_).
    #
    # .. _`Section 3.4.1.2`: http://tools.ietf.org/html/rfc5849#section-3.4.1.2
    # .. _`Section 3.4.6`: http://tools.ietf.org/html/rfc5849#section-3.4.6
    base_string += utils.escape(base_string_uri)

    # 4.  An "&" character (ASCII code 38).
    base_string += u'&'

    # 5.  The request parameters as normalized in `Section 3.4.1.3.2`_, after
    #     being encoded (`Section 3.6`).
    #
    # .. _`Section 3.4.1.3.2`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
    # .. _`Section 3.4.6`: http://tools.ietf.org/html/rfc5849#section-3.4.6
    base_string += utils.escape(normalized_encoded_request_parameters)

    return base_string


def normalize_base_string_uri(uri):
    """**Base String URI**
    Per `section 3.4.1.2`_ of the spec.

    For example, the HTTP request::

        GET /r%20v/X?id=123 HTTP/1.1
        Host: EXAMPLE.COM:80

    is represented by the base string URI: "http://example.com/r%20v/X".

    In another example, the HTTPS request::

        GET /?q=1 HTTP/1.1
        Host: www.example.net:8080

    is represented by the base string URI: "https://www.example.net:8080/".

    .. _`section 3.4.1.2`: http://tools.ietf.org/html/rfc5849#section-3.4.1.2
    """
    if not isinstance(uri, unicode):
        raise ValueError('uri must be a unicode object.')

    # FIXME: urlparse does not support unicode
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(uri)

    # The scheme, authority, and path of the request resource URI `RFC3986`
    # are included by constructing an "http" or "https" URI representing
    # the request resource (without the query or fragment) as follows:
    #
    # .. _`RFC2616`: http://tools.ietf.org/html/rfc3986

    # 1.  The scheme and host MUST be in lowercase.
    scheme = scheme.lower()
    netloc = netloc.lower()

    # 2.  The host and port values MUST match the content of the HTTP
    #     request "Host" header field.
    # TODO: enforce this constraint

    # 3.  The port MUST be included if it is not the default port for the
    #     scheme, and MUST be excluded if it is the default.  Specifically,
    #     the port MUST be excluded when making an HTTP request `RFC2616`_
    #     to port 80 or when making an HTTPS request `RFC2818`_ to port 443.
    #     All other non-default port numbers MUST be included.
    #
    # .. _`RFC2616`: http://tools.ietf.org/html/rfc2616
    # .. _`RFC2818`: http://tools.ietf.org/html/rfc2818
    default_ports = (
        (u'http', u'80'),
        (u'https', u'443'),
    )
    if u':' in netloc:
        host, port = netloc.split(u':', 1)
        if (scheme, port) in default_ports:
            netloc = host

    return urlparse.urlunparse((scheme, netloc, path, u'', u'', u''))


# ** Request Parameters **
#
#    Per `section 3.4.1.3`_ of the spec.
#
#    In order to guarantee a consistent and reproducible representation of
#    the request parameters, the parameters are collected and decoded to
#    their original decoded form.  They are then sorted and encoded in a
#    particular manner that is often different from their original
#    encoding scheme, and concatenated into a single string.
#
#    .. _`section 3.4.1.3`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3

def collect_parameters(uri_query='', body=[], headers=None,
        exclude_oauth_signature=True):
    """**Parameter Sources**

    Parameters starting with `oauth_` will be unescaped.

    Body parameters must be supplied as a dict, a list of 2-tuples, or a
    formencoded query string.

    Headers must be supplied as a dict.

    Per `section 3.4.1.3.1`_ of the spec.

    For example, the HTTP request::

        POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
        Host: example.com
        Content-Type: application/x-www-form-urlencoded
        Authorization: OAuth realm="Example",
            oauth_consumer_key="9djdj82h48djs9d2",
            oauth_token="kkk9d7dh3k39sjv7",
            oauth_signature_method="HMAC-SHA1",
            oauth_timestamp="137131201",
            oauth_nonce="7d8f3e4a",
            oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D"

        c2&a3=2+q

    contains the following (fully decoded) parameters used in the
    signature base sting::

        +------------------------+------------------+
        |          Name          |       Value      |
        +------------------------+------------------+
        |           b5           |       =%3D       |
        |           a3           |         a        |
        |           c@           |                  |
        |           a2           |        r b       |
        |   oauth_consumer_key   | 9djdj82h48djs9d2 |
        |       oauth_token      | kkk9d7dh3k39sjv7 |
        | oauth_signature_method |     HMAC-SHA1    |
        |     oauth_timestamp    |     137131201    |
        |       oauth_nonce      |     7d8f3e4a     |
        |           c2           |                  |
        |           a3           |        2 q       |
        +------------------------+------------------+

    Note that the value of "b5" is "=%3D" and not "==".  Both "c@" and
    "c2" have empty values.  While the encoding rules specified in this
    specification for the purpose of constructing the signature base
    string exclude the use of a "+" character (ASCII code 43) to
    represent an encoded space character (ASCII code 32), this practice
    is widely used in "application/x-www-form-urlencoded" encoded values,
    and MUST be properly decoded, as demonstrated by one of the "a3"
    parameter instances (the "a3" parameter is used twice in this
    request).

    .. _`section 3.4.1.3.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3.1
    """
    headers = headers or {}
    params = []

    # The parameters from the following sources are collected into a single
    # list of name/value pairs:

    # *  The query component of the HTTP request URI as defined by
    #    `RFC3986, Section 3.4`_.  The query component is parsed into a list
    #    of name/value pairs by treating it as an
    #    "application/x-www-form-urlencoded" string, separating the names
    #    and values and decoding them as defined by
    #    `W3C.REC-html40-19980424`_, Section 17.13.4.
    #
    # .. _`RFC3986, Section 3.4`: http://tools.ietf.org/html/rfc3986#section-3.4
    # .. _`W3C.REC-html40-19980424`: http://tools.ietf.org/html/rfc5849#ref-W3C.REC-html40-19980424
    if uri_query:
        params.extend(urlparse.parse_qsl(uri_query, keep_blank_values=True))

    # *  The OAuth HTTP "Authorization" header field (`Section 3.5.1`_) if
    #    present.  The header's content is parsed into a list of name/value
    #    pairs excluding the "realm" parameter if present.  The parameter
    #    values are decoded as defined by `Section 3.5.1`_.
    #
    # .. _`Section 3.5.1`: http://tools.ietf.org/html/rfc5849#section-3.5.1
    if headers:
        headers_lower = dict((k.lower(), v) for k, v in headers.items())
        authorization_header = headers_lower.get(u'authorization')
        if authorization_header is not None:
            params.extend([i for i in utils.parse_authorization_header(
                authorization_header) if i[0] != u'realm'])

    # *  The HTTP request entity-body, but only if all of the following
    #    conditions are met:
    #     *  The entity-body is single-part.
    #
    #     *  The entity-body follows the encoding requirements of the
    #        "application/x-www-form-urlencoded" content-type as defined by
    #        `W3C.REC-html40-19980424`_.

    #     *  The HTTP request entity-header includes the "Content-Type"
    #        header field set to "application/x-www-form-urlencoded".
    #
    # .._`W3C.REC-html40-19980424`: http://tools.ietf.org/html/rfc5849#ref-W3C.REC-html40-19980424

    # TODO: enforce header param inclusion conditions
    bodyparams = extract_params(body) or []
    params.extend(bodyparams)

    # ensure all oauth params are unescaped
    unescaped_params = []
    for k, v in params:
        if k.startswith(u'oauth_'):
            v = utils.unescape(v)
        unescaped_params.append((k, v))

    # The "oauth_signature" parameter MUST be excluded from the signature
    # base string if present.
    if exclude_oauth_signature:
        unescaped_params = filter(lambda i: i[0] != u'oauth_signature',
            unescaped_params)

    return unescaped_params


def normalize_parameters(params):
    """**Parameters Normalization**
    Per `section 3.4.1.3.2`_ of the spec.

    For example, the list of parameters from the previous section would
    be normalized as follows:

    Encoded::

    +------------------------+------------------+
    |          Name          |       Value      |
    +------------------------+------------------+
    |           b5           |     %3D%253D     |
    |           a3           |         a        |
    |          c%40          |                  |
    |           a2           |       r%20b      |
    |   oauth_consumer_key   | 9djdj82h48djs9d2 |
    |       oauth_token      | kkk9d7dh3k39sjv7 |
    | oauth_signature_method |     HMAC-SHA1    |
    |     oauth_timestamp    |     137131201    |
    |       oauth_nonce      |     7d8f3e4a     |
    |           c2           |                  |
    |           a3           |       2%20q      |
    +------------------------+------------------+

    Sorted::

    +------------------------+------------------+
    |          Name          |       Value      |
    +------------------------+------------------+
    |           a2           |       r%20b      |
    |           a3           |       2%20q      |
    |           a3           |         a        |
    |           b5           |     %3D%253D     |
    |          c%40          |                  |
    |           c2           |                  |
    |   oauth_consumer_key   | 9djdj82h48djs9d2 |
    |       oauth_nonce      |     7d8f3e4a     |
    | oauth_signature_method |     HMAC-SHA1    |
    |     oauth_timestamp    |     137131201    |
    |       oauth_token      | kkk9d7dh3k39sjv7 |
    +------------------------+------------------+

    Concatenated Pairs::

    +-------------------------------------+
    |              Name=Value             |
    +-------------------------------------+
    |               a2=r%20b              |
    |               a3=2%20q              |
    |                 a3=a                |
    |             b5=%3D%253D             |
    |                c%40=                |
    |                 c2=                 |
    | oauth_consumer_key=9djdj82h48djs9d2 |
    |         oauth_nonce=7d8f3e4a        |
    |   oauth_signature_method=HMAC-SHA1  |
    |      oauth_timestamp=137131201      |
    |     oauth_token=kkk9d7dh3k39sjv7    |
    +-------------------------------------+

    and concatenated together into a single string (line breaks are for
    display purposes only)::

        a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj
        dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1
        &oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7

    .. _`section 3.4.1.3.2`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
    """

    # The parameters collected in `Section 3.4.1.3`_ are normalized into a
    # single string as follows:
    #
    # .. _`Section 3.4.1.3`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3

    # 1.  First, the name and value of each parameter are encoded
    #     (`Section 3.6`_).
    #
    # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
    key_values = [(utils.escape(k), utils.escape(v)) for k, v in params]

    # 2.  The parameters are sorted by name, using ascending byte value
    #     ordering.  If two or more parameters share the same name, they
    #     are sorted by their value.
    key_values.sort()

    # 3.  The name of each parameter is concatenated to its corresponding
    #     value using an "=" character (ASCII code 61) as a separator, even
    #     if the value is empty.
    parameter_parts = [u'{0}={1}'.format(k, v) for k, v in key_values]

    # 4.  The sorted name/value pairs are concatenated together into a
    #     single string by using an "&" character (ASCII code 38) as
    #     separator.
    return u'&'.join(parameter_parts)


def sign_hmac_sha1(base_string, client_secret, resource_owner_secret):
    """**HMAC-SHA1**

    The "HMAC-SHA1" signature method uses the HMAC-SHA1 signature
    algorithm as defined in `RFC2104`_::

        digest = HMAC-SHA1 (key, text)

    Per `section 3.4.2`_ of the spec.

    .. _`RFC2104`: http://tools.ietf.org/html/rfc2104
    .. _`section 3.4.2`: http://tools.ietf.org/html/rfc5849#section-3.4.2
    """

    # The HMAC-SHA1 function variables are used in following way:

    # text is set to the value of the signature base string from
    # `Section 3.4.1.1`_.
    #
    # .. _`Section 3.4.1.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1.1
    text = base_string

    # key is set to the concatenated values of:
    # 1.  The client shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
    key = utils.escape(client_secret or u'')

    # 2.  An "&" character (ASCII code 38), which MUST be included
    #     even when either secret is empty.
    key += u'&'

    # 3.  The token shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
    key += utils.escape(resource_owner_secret or u'')

    # FIXME: HMAC does not support unicode!
    key_utf8 = key.encode('utf-8')
    text_utf8 = text.encode('utf-8')
    signature = hmac.new(key_utf8, text_utf8, hashlib.sha1)

    # digest  is used to set the value of the "oauth_signature" protocol
    #         parameter, after the result octet string is base64-encoded
    #         per `RFC2045, Section 6.8`.
    #
    # .. _`RFC2045, Section 6.8`: http://tools.ietf.org/html/rfc2045#section-6.8
    return binascii.b2a_base64(signature.digest())[:-1].decode('utf-8')


def sign_rsa_sha1(base_string, rsa_private_key):
    """**RSA-SHA1**

    Per `section 3.4.3`_ of the spec.

    The "RSA-SHA1" signature method uses the RSASSA-PKCS1-v1_5 signature
    algorithm as defined in `RFC3447, Section 8.2`_ (also known as
    PKCS#1), using SHA-1 as the hash function for EMSA-PKCS1-v1_5.  To
    use this method, the client MUST have established client credentials
    with the server that included its RSA public key (in a manner that is
    beyond the scope of this specification).

    NOTE: this method requires the python-rsa library.

    .. _`section 3.4.3`: http://tools.ietf.org/html/rfc5849#section-3.4.3
    .. _`RFC3447, Section 8.2`: http://tools.ietf.org/html/rfc3447#section-8.2

    """
    # TODO: finish RSA documentation
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA
    key = RSA.importKey(rsa_private_key)
    h = SHA.new(base_string)
    p = PKCS1_v1_5.new(key)
    return binascii.b2a_base64(p.sign(h))[:-1].decode('utf-8')


def sign_plaintext(client_secret, resource_owner_secret):
    """Sign a request using plaintext.

    Per `section 3.4.4`_ of the spec.

    The "PLAINTEXT" method does not employ a signature algorithm.  It
    MUST be used with a transport-layer mechanism such as TLS or SSL (or
    sent over a secure channel with equivalent protections).  It does not
    utilize the signature base string or the "oauth_timestamp" and
    "oauth_nonce" parameters.

    .. _`section 3.4.4`: http://tools.ietf.org/html/rfc5849#section-3.4.4

    """

    # The "oauth_signature" protocol parameter is set to the concatenated
    # value of:

    # 1.  The client shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
    signature = utils.escape(client_secret or u'')

    # 2.  An "&" character (ASCII code 38), which MUST be included even
    #     when either secret is empty.
    signature += u'&'

    # 3.  The token shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
    signature += utils.escape(resource_owner_secret or u'')

    return signature


def verify_hmac_sha1(request, client_secret=None, 
    resource_owner_secret=None):
    """Verify a HMAC-SHA1 signature.

    Per `section 3.4`_ of the spec.

    .. _`section 3.4`: http://tools.ietf.org/html/rfc5849#section-3.4
    """
    norm_params = normalize_parameters(request.params)
    uri = normalize_base_string_uri(request.uri)
    base_string = construct_base_string(request.http_method, uri, norm_params)
    signature = sign_hmac_sha1(base_string, client_secret,
        resource_owner_secret)
    return safe_string_equals(signature, request.signature)


def verify_rsa_sha1(request, rsa_public_key):
    """Verify a RSASSA-PKCS #1 v1.5 base64 encoded signature.

    Per `section 3.4.3`_ of the spec.

    Note this method requires the PyCrypto library.

    .. _`section 3.4.3`: http://tools.ietf.org/html/rfc5849#section-3.4.3

    """
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA
    key = RSA.importKey(rsa_public_key)
    norm_params = normalize_parameters(request.params)
    uri = normalize_base_string_uri(request.uri)
    message = construct_base_string(request.http_method, uri, norm_params)
    h = SHA.new(message)
    p = PKCS1_v1_5.new(key)
    sig = binascii.a2b_base64(request.signature)
    return p.verify(h, sig)


def verify_plaintext(request, client_secret=None, resource_owner_secret=None):
    """Verify a PLAINTEXT signature.

    Per `section 3.4`_ of the spec.

    .. _`section 3.4`: http://tools.ietf.org/html/rfc5849#section-3.4
    """
    signature = sign_plaintext(client_secret, resource_owner_secret)
    return safe_string_equals(signature, request.signature)
