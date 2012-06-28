from __future__ import absolute_import
"""
oauthlib.oauth2.draft25.tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains methods for adding two types of access tokens to requests.

- Bearer http://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-08
- MAC http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-00

"""
from binascii import b2a_base64
import hashlib
import hmac
from urlparse import urlparse

from oauthlib.common import add_params_to_uri, add_params_to_qs
from . import utils


def prepare_mac_header(token, uri, key, http_method, nonce=None, headers=None,
        body=None, ext=u'', hash_algorithm=u'hmac-sha-1'):
    """Add an `MAC Access Authentication`_ signature to headers.

    Unlike OAuth 1, this HMAC signature does not require inclusion of the request
    payload/body, neither does it use a combination of client_secret and
    token_secret but rather a mac_key provided together with the access token.

    Currently two algorithms are supported, "hmac-sha-1" and "hmac-sha-256",
    `extension algorithms`_ are not supported.

    Example MAC Authorization header, linebreaks added for clarity

    Authorization: MAC id="h480djs93hd8",
                       nonce="1336363200:dj83hs9s",
                       mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="

    .. _`MAC Access Authentication`: http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01
    .. _`extension algorithms`: http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01#section-7.1

    :param uri: Request URI.
    :param headers: Request headers as a dictionary.
    :param http_method: HTTP Request method.
    :param key: MAC given provided by token endpoint.
    :param algorithm: HMAC algorithm provided by token endpoint.
    :return: headers dictionary with the authorization field added.
    """
    http_method = http_method.upper()
    host, port = utils.host_from_uri(uri)

    if hash_algorithm.lower() == u'hmac-sha-1':
        h = hashlib.sha1
    else:
        h = hashlib.sha256

    nonce = nonce or u'{0}:{1}'.format(utils.generate_nonce(), utils.generate_timestamp())
    sch, net, path, par, query, fra = urlparse(uri)

    if query:
        request_uri = path + u'?' + query
    else:
        request_uri = path

    # Hash the body/payload
    if body is not None:
        bodyhash = b2a_base64(h(body).digest())[:-1].decode('utf-8')
    else:
        bodyhash = u''

    # Create the normalized base string
    base = []
    base.append(nonce)
    base.append(http_method.upper())
    base.append(request_uri)
    base.append(host)
    base.append(port)
    base.append(bodyhash)
    base.append(ext)
    base_string = '\n'.join(base) + u'\n'

    # hmac struggles with unicode strings - http://bugs.python.org/issue5285
    if isinstance(key, unicode):
        key = key.encode('utf-8')
    sign = hmac.new(key, base_string, h)
    sign = b2a_base64(sign.digest())[:-1].decode('utf-8')

    header = []
    header.append(u'MAC id="%s"' % token)
    header.append(u'nonce="%s"' % nonce)
    if bodyhash:
        header.append(u'bodyhash="%s"' % bodyhash)
    if ext:
        header.append(u'ext="%s"' % ext)
    header.append(u'mac="%s"' % sign)

    headers = headers or {}
    headers[u'Authorization'] = u', '.join(header)
    return headers


def prepare_bearer_uri(token, uri):
    """Add a `Bearer Token`_ to the request URI.
    Not recommended, use only if client can't use authorization header or body.

    http://www.example.com/path?access_token=h480djs93hd8

    .. _`Bearer Token`: http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-18
    """
    return add_params_to_uri(uri, [((u'access_token', token))])


def prepare_bearer_headers(token, headers=None):
    """Add a `Bearer Token`_ to the request URI.
    Recommended method of passing bearer tokens.

    Authorization: Bearer h480djs93hd8

    .. _`Bearer Token`: http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-18
    """
    headers = headers or {}
    headers[u'Authorization'] = u'Bearer %s' % token
    return headers


def prepare_bearer_body(token, body=u''):
    """Add a `Bearer Token`_ to the request body.

    access_token=h480djs93hd8

    .. _`Bearer Token`: http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-18
    """
    return add_params_to_qs(body, [((u'access_token', token))])
