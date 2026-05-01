# -*- coding: utf-8 -*-

"""
httpbin.helpers
~~~~~~~~~~~~~~~

This module provides helper functions for httpbin.
"""

import json
import base64
import re
import time
import os
from hashlib import md5, sha256, sha512
from werkzeug.datastructures import WWWAuthenticate
from werkzeug.http import dump_header

try:
    from werkzeug.http import parse_authorization_header
except ImportError: # werkzeug < 2.3
    from werkzeug.datastructures import Authorization
    parse_authorization_header = Authorization.from_header

from flask import request, make_response
from six.moves.urllib.parse import urlparse, urlunparse


from .structures import CaseInsensitiveDict


ASCII_ART = """
    -=[ teapot ]=-

       _...._
     .'  _ _ `.
    | ."` ^ `". _,
    \_;`"---"`|//
      |       ;/
      \_     _/
        `\"\"\"`
"""

REDIRECT_LOCATION = '/redirect/1'

ENV_HEADERS = (
    'X-Varnish',
    'X-Request-Start',
    'X-Heroku-Queue-Depth',
    'X-Real-Ip',
    'X-Forwarded-Proto',
    'X-Forwarded-Protocol',
    'X-Forwarded-Ssl',
    'X-Heroku-Queue-Wait-Time',
    'X-Forwarded-For',
    'X-Heroku-Dynos-In-Use',
    'X-Forwarded-Protocol',
    'X-Forwarded-Port',
    'X-Request-Id',
    'Via',
    'Total-Route-Time',
    'Connect-Time'
)

ROBOT_TXT = """User-agent: *
Disallow: /deny
"""

ACCEPTED_MEDIA_TYPES = [
    'image/webp',
    'image/svg+xml',
    'image/jpeg',
    'image/png',
    'image/*'
]

ANGRY_ASCII ="""
          .-''''''-.
        .' _      _ '.
       /   O      O   \\
      :                :
      |                |
      :       __       :
       \  .-"`  `"-.  /
        '.          .'
          '-......-'
     YOU SHOULDN'T BE HERE
"""


def json_safe(string, content_type='application/octet-stream'):
    """Returns JSON-safe version of `string`.

    If `string` is a Unicode string or a valid UTF-8, it is returned unmodified,
    as it can safely be encoded to JSON string.

    If `string` contains raw/binary data, it is Base64-encoded, formatted and
    returned according to "data" URL scheme (RFC2397). Since JSON is not
    suitable for binary data, some additional encoding was necessary; "data"
    URL scheme was chosen for its simplicity.
    """
    try:
        string = string.decode('utf-8')
        json.dumps(string)
        return string
    except (ValueError, TypeError):
        return b''.join([
            b'data:',
            content_type.encode('utf-8'),
            b';base64,',
            base64.b64encode(string)
        ]).decode('utf-8')


def get_files():
    """Returns files dict from request context."""

    files = dict()

    for k, v in request.files.items():
        content_type = request.files[k].content_type or 'application/octet-stream'
        val = json_safe(v.read(), content_type)
        if files.get(k):
            if not isinstance(files[k], list):
                files[k] = [files[k]]
            files[k].append(val)
        else:
            files[k] = val

    return files


def get_headers(hide_env=True):
    """Returns headers dict from request context."""

    headers = dict(request.headers.items())

    if hide_env and ('show_env' not in request.args):
        for key in ENV_HEADERS:
            try:
                del headers[key]
            except KeyError:
                pass

    return CaseInsensitiveDict(headers.items())


def semiflatten(multi):
    """Convert a MutiDict into a regular dict. If there are more than one value
    for a key, the result will have a list of values for the key. Otherwise it
    will have the plain value."""
    if multi:
        result = multi.to_dict(flat=False)
        for k, v in result.items():
            if len(v) == 1:
                result[k] = v[0]
        return result
    else:
        return multi

def get_url(request):
    """
    Since we might be hosted behind a proxy, we need to check the
    X-Forwarded-Proto, X-Forwarded-Protocol, or X-Forwarded-SSL headers
    to find out what protocol was used to access us.
    """
    protocol = request.headers.get('X-Forwarded-Proto') or request.headers.get('X-Forwarded-Protocol')
    if protocol is None and request.headers.get('X-Forwarded-Ssl') == 'on':
        protocol = 'https'
    if protocol is None:
        return request.url
    url = list(urlparse(request.url))
    url[0] = protocol
    return urlunparse(url)


def get_dict(*keys, **extras):
    """Returns request dict of given keys."""

    _keys = ('url', 'args', 'form', 'data', 'origin', 'headers', 'files', 'json', 'method')

    assert all(map(_keys.__contains__, keys))
    data = request.data
    form = semiflatten(request.form)

    try:
        _json = json.loads(data.decode('utf-8'))
    except (ValueError, TypeError):
        _json = None

    d = dict(
        url=get_url(request),
        args=semiflatten(request.args),
        form=form,
        data=json_safe(data),
        origin=request.headers.get('X-Forwarded-For', request.remote_addr),
        headers=get_headers(),
        files=get_files(),
        json=_json,
        method=request.method,
    )

    out_d = dict()

    for key in keys:
        out_d[key] = d.get(key)

    out_d.update(extras)

    return out_d


def status_code(code):
    """Returns response object of given status code."""

    redirect = dict(headers=dict(location=REDIRECT_LOCATION))

    code_map = {
        301: redirect,
        302: redirect,
        303: redirect,
        304: dict(data=''),
        305: redirect,
        307: redirect,
        401: dict(headers={'WWW-Authenticate': 'Basic realm="Fake Realm"'}),
        402: dict(
            data='Fuck you, pay me!',
            headers={
                'x-more-info': 'http://vimeo.com/22053820'
            }
        ),
        406: dict(data=json.dumps({
                'message': 'Client did not request a supported media type.',
                'accept': ACCEPTED_MEDIA_TYPES
            }),
            headers={
                'Content-Type': 'application/json'
            }),
        407: dict(headers={'Proxy-Authenticate': 'Basic realm="Fake Realm"'}),
        418: dict(  # I'm a teapot!
            data=ASCII_ART,
            headers={
                'x-more-info': 'http://tools.ietf.org/html/rfc2324'
            }
        ),

    }

    r = make_response()
    r.status_code = code

    if code in code_map:

        m = code_map[code]

        if 'data' in m:
            r.data = m['data']
        if 'headers' in m:
            r.headers = m['headers']

    return r


def check_basic_auth(user, passwd):
    """Checks user authentication using HTTP Basic Auth."""

    auth = request.authorization
    return auth and auth.username == user and auth.password == passwd



# Digest auth helpers
# qop is a quality of protection

def H(data, algorithm):
    if algorithm == 'SHA-256':
        return sha256(data).hexdigest()
    elif algorithm == 'SHA-512':
        return sha512(data).hexdigest()
    else:
        return md5(data).hexdigest()


def HA1(realm, username, password, algorithm):
    """Create HA1 hash by realm, username, password

    HA1 = md5(A1) = MD5(username:realm:password)
    """
    if not realm:
        realm = u''
    return H(b":".join([username.encode('utf-8'),
                           realm.encode('utf-8'),
                           password.encode('utf-8')]), algorithm)


def HA2(credentials, request, algorithm):
    """Create HA2 md5 hash

    If the qop directive's value is "auth" or is unspecified, then HA2:
        HA2 = md5(A2) = MD5(method:digestURI)
    If the qop directive's value is "auth-int" , then HA2 is
        HA2 = md5(A2) = MD5(method:digestURI:MD5(entityBody))
    """
    if credentials.get("qop") == "auth" or credentials.get('qop') is None:
        return H(b":".join([request['method'].encode('utf-8'), request['uri'].encode('utf-8')]), algorithm)
    elif credentials.get("qop") == "auth-int":
        for k in 'method', 'uri', 'body':
            if k not in request:
                raise ValueError("%s required" % k)
        A2 = b":".join([request['method'].encode('utf-8'),
                        request['uri'].encode('utf-8'),
                        H(request['body'], algorithm).encode('utf-8')])
        return H(A2, algorithm)
    raise ValueError


def response(credentials, password, request):
    """Compile digest auth response

    If the qop directive's value is "auth" or "auth-int" , then compute the response as follows:
       RESPONSE = MD5(HA1:nonce:nonceCount:clienNonce:qop:HA2)
    Else if the qop directive is unspecified, then compute the response as follows:
       RESPONSE = MD5(HA1:nonce:HA2)

    Arguments:
    - `credentials`: credentials dict
    - `password`: request user password
    - `request`: request dict
    """
    response = None
    algorithm = credentials.get('algorithm')
    HA1_value = HA1(
        credentials.get('realm'),
        credentials.get('username'),
        password,
        algorithm
    )
    HA2_value = HA2(credentials, request, algorithm)
    if credentials.get('qop') is None:
        response = H(b":".join([
            HA1_value.encode('utf-8'),
            credentials.get('nonce', '').encode('utf-8'),
            HA2_value.encode('utf-8')
        ]), algorithm)
    elif credentials.get('qop') == 'auth' or credentials.get('qop') == 'auth-int':
        for k in 'nonce', 'nc', 'cnonce', 'qop':
            if k not in credentials:
                raise ValueError("%s required for response H" % k)
        response = H(b":".join([HA1_value.encode('utf-8'),
                               credentials.get('nonce').encode('utf-8'),
                               credentials.get('nc').encode('utf-8'),
                               credentials.get('cnonce').encode('utf-8'),
                               credentials.get('qop').encode('utf-8'),
                               HA2_value.encode('utf-8')]), algorithm)
    else:
        raise ValueError("qop value are wrong")

    return response


def check_digest_auth(user, passwd):
    """Check user authentication using HTTP Digest auth"""

    if request.headers.get('Authorization'):
        credentials = parse_authorization_header(request.headers.get('Authorization'))
        if not credentials:
            return
        request_uri = request.script_root + request.path
        if request.query_string:
            request_uri +=  '?' + request.query_string
        response_hash = response(credentials, passwd, dict(uri=request_uri,
                                                           body=request.data,
                                                           method=request.method))
        if credentials.get('response') == response_hash:
            return True
    return False

def secure_cookie():
    """Return true if cookie should have secure attribute"""
    return request.environ['wsgi.url_scheme'] == 'https'

def __parse_request_range(range_header_text):
    """ Return a tuple describing the byte range requested in a GET request
    If the range is open ended on the left or right side, then a value of None
    will be set.
    RFC7233: http://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7233.html#header.range
    Examples:
      Range : bytes=1024-
      Range : bytes=10-20
      Range : bytes=-999
    """

    left = None
    right = None

    if not range_header_text:
        return left, right

    range_header_text = range_header_text.strip()
    if not range_header_text.startswith('bytes'):
        return left, right

    components = range_header_text.split("=")
    if len(components) != 2:
        return left, right

    components = components[1].split("-")

    try:
        right = int(components[1])
    except:
        pass

    try:
        left = int(components[0])
    except:
        pass

    return left, right

def get_request_range(request_headers, upper_bound):
    first_byte_pos, last_byte_pos = __parse_request_range(request_headers['range'])

    if first_byte_pos is None and last_byte_pos is None:
        # Request full range
        first_byte_pos = 0
        last_byte_pos = upper_bound - 1
    elif first_byte_pos is None:
        # Request the last X bytes
        first_byte_pos = max(0, upper_bound - last_byte_pos)
        last_byte_pos = upper_bound - 1
    elif last_byte_pos is None:
        # Request the last X bytes
        last_byte_pos = upper_bound - 1

    return first_byte_pos, last_byte_pos

def parse_multi_value_header(header_str):
    """Break apart an HTTP header string that is potentially a quoted, comma separated list as used in entity headers in RFC2616."""
    parsed_parts = []
    if header_str:
        parts = header_str.split(',')
        for part in parts:
            match = re.search('\s*(W/)?\"?([^"]*)\"?\s*', part)
            if match is not None:
                parsed_parts.append(match.group(2))
    return parsed_parts


def next_stale_after_value(stale_after):
    try:
        stal_after_count = int(stale_after) - 1
        return str(stal_after_count)
    except ValueError:
        return 'never'


def digest_challenge_response(app, qop, algorithm, stale = False):
    response = app.make_response('')
    response.status_code = 401

    # RFC2616 Section4.2: HTTP headers are ASCII.  That means
    # request.remote_addr was originally ASCII, so I should be able to
    # encode it back to ascii.  Also, RFC2617 says about nonces: "The
    # contents of the nonce are implementation dependent"
    nonce = H(b''.join([
        getattr(request, 'remote_addr', u'').encode('ascii'),
        b':',
        str(time.time()).encode('ascii'),
        b':',
        os.urandom(10)
    ]), algorithm)
    opaque = H(os.urandom(10), algorithm)

    values = {
        'realm': 'me@kennethreitz.com',
        'nonce': nonce,
        'opaque': opaque,
        'qop': dump_header(('auth', 'auth-int') if qop is None else (qop,)),
        'algorithm': algorithm,
        'stale': stale,
    }
    auth = WWWAuthenticate("digest", values=values)
    response.headers['WWW-Authenticate'] = auth.to_header()
    return response
