# -*- coding: utf-8 -*-

"""
requests.utils
~~~~~~~~~~~~~~

This module provides utility functions that are used within Requests
that are also useful for external consumption.

"""

import cgi
import codecs
import random
import re
import zlib

from .compat import parse_http_list as _parse_list_header
from .compat import quote, cookielib, SimpleCookie, is_py2
from .compat import basestring, bytes


def dict_from_string(s):
    """Returns a MultiDict with Cookies."""

    cookies = dict()

    c = SimpleCookie()
    c.load(s)

    for k, v in list(c.items()):
        cookies.update({k: v.value})

    return cookies


def guess_filename(obj):
    """Tries to guess the filename of the given object."""
    name = getattr(obj, 'name', None)
    if name and name[0] != '<' and name[-1] != '>':
        return name


# From mitsuhiko/werkzeug (used with permission).
def parse_list_header(value):
    """Parse lists as described by RFC 2068 Section 2.

    In particular, parse comma-separated lists where the elements of
    the list may include quoted-strings.  A quoted-string could
    contain a comma.  A non-quoted string could have quotes in the
    middle.  Quotes are removed automatically after parsing.

    It basically works like :func:`parse_set_header` just that items
    may appear multiple times and case sensitivity is preserved.

    The return value is a standard :class:`list`:

    >>> parse_list_header('token, "quoted value"')
    ['token', 'quoted value']

    To create a header from the :class:`list` again, use the
    :func:`dump_header` function.

    :param value: a string with a list header.
    :return: :class:`list`
    """
    result = []
    for item in _parse_list_header(value):
        if item[:1] == item[-1:] == '"':
            item = unquote_header_value(item[1:-1])
        result.append(item)
    return result


# From mitsuhiko/werkzeug (used with permission).
def parse_dict_header(value):
    """Parse lists of key, value pairs as described by RFC 2068 Section 2 and
    convert them into a python dict:

    >>> d = parse_dict_header('foo="is a fish", bar="as well"')
    >>> type(d) is dict
    True
    >>> sorted(d.items())
    [('bar', 'as well'), ('foo', 'is a fish')]

    If there is no value for a key it will be `None`:

    >>> parse_dict_header('key_without_value')
    {'key_without_value': None}

    To create a header from the :class:`dict` again, use the
    :func:`dump_header` function.

    :param value: a string with a dict header.
    :return: :class:`dict`
    """
    result = {}
    for item in _parse_list_header(value):
        if '=' not in item:
            result[item] = None
            continue
        name, value = item.split('=', 1)
        if value[:1] == value[-1:] == '"':
            value = unquote_header_value(value[1:-1])
        result[name] = value
    return result


# From mitsuhiko/werkzeug (used with permission).
def unquote_header_value(value, is_filename=False):
    r"""Unquotes a header value.  (Reversal of :func:`quote_header_value`).
    This does not use the real unquoting but what browsers are actually
    using for quoting.

    :param value: the header value to unquote.
    """
    if value and value[0] == value[-1] == '"':
        # this is not the real unquoting, but fixing this so that the
        # RFC is met will result in bugs with internet explorer and
        # probably some other browsers as well.  IE for example is
        # uploading files with "C:\foo\bar.txt" as filename
        value = value[1:-1]

        # if this is a filename and the starting characters look like
        # a UNC path, then just return the value without quotes.  Using the
        # replace sequence below on a UNC path has the effect of turning
        # the leading double slash into a single slash and then
        # _fix_ie_filename() doesn't work correctly.  See #458.
        if not is_filename or value[:2] != '\\\\':
            return value.replace('\\\\', '\\').replace('\\"', '"')
    return value


def header_expand(headers):
    """Returns an HTTP Header value string from a dictionary.

    Example expansion::

        {'text/x-dvi': {'q': '.8', 'mxb': '100000', 'mxt': '5.0'}, 'text/x-c': {}}
        # Accept: text/x-dvi; q=.8; mxb=100000; mxt=5.0, text/x-c

        (('text/x-dvi', {'q': '.8', 'mxb': '100000', 'mxt': '5.0'}), ('text/x-c', {}))
        # Accept: text/x-dvi; q=.8; mxb=100000; mxt=5.0, text/x-c
    """

    collector = []

    if isinstance(headers, dict):
        headers = list(headers.items())
    elif isinstance(headers, basestring):
        return headers
    elif isinstance(headers, unicode):
        # As discussed in https://github.com/kennethreitz/requests/issues/400
        # latin-1 is the most conservative encoding used on the web. Anyone
        # who needs more can encode to a byte-string before calling
        return headers.encode("latin-1")
    elif headers is None:
        return headers

    for i, (value, params) in enumerate(headers):

        _params = []

        for (p_k, p_v) in list(params.items()):

            _params.append('%s=%s' % (p_k, p_v))

        collector.append(value)
        collector.append('; ')

        if len(params):

            collector.append('; '.join(_params))

            if not len(headers) == i + 1:
                collector.append(', ')

    # Remove trailing separators.
    if collector[-1] in (', ', '; '):
        del collector[-1]

    return ''.join(collector)


def randombytes(n):
    """Return n random bytes."""
    if is_py2:
        L = [chr(random.randrange(0, 256)) for i in range(n)]
    else:
        L = [chr(random.randrange(0, 256)).encode('utf-8') for i in range(n)]
    return b"".join(L)


def dict_from_cookiejar(cj):
    """Returns a key/value dictionary from a CookieJar.

    :param cj: CookieJar object to extract cookies from.
    """

    cookie_dict = {}

    for _, cookies in list(cj._cookies.items()):
        for _, cookies in list(cookies.items()):
            for cookie in list(cookies.values()):
                # print cookie
                cookie_dict[cookie.name] = cookie.value

    return cookie_dict


def cookiejar_from_dict(cookie_dict):
    """Returns a CookieJar from a key/value dictionary.

    :param cookie_dict: Dict of key/values to insert into CookieJar.
    """

    # return cookiejar if one was passed in
    if isinstance(cookie_dict, cookielib.CookieJar):
        return cookie_dict

    # create cookiejar
    cj = cookielib.CookieJar()

    cj = add_dict_to_cookiejar(cj, cookie_dict)

    return cj


def add_dict_to_cookiejar(cj, cookie_dict):
    """Returns a CookieJar from a key/value dictionary.

    :param cj: CookieJar to insert cookies into.
    :param cookie_dict: Dict of key/values to insert into CookieJar.
    """

    for k, v in list(cookie_dict.items()):

        cookie = cookielib.Cookie(
            version=0,
            name=k,
            value=v,
            port=None,
            port_specified=False,
            domain='',
            domain_specified=False,
            domain_initial_dot=False,
            path='/',
            path_specified=True,
            secure=False,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={'HttpOnly': None},
            rfc2109=False
        )

        # add cookie to cookiejar
        cj.set_cookie(cookie)

    return cj


def get_encodings_from_content(content):
    """Returns encodings from given content string.

    :param content: bytestring to extract encodings from.
    """

    charset_re = re.compile(r'<meta.*?charset=["\']*(.+?)["\'>]', flags=re.I)

    return charset_re.findall(content)


def get_encoding_from_headers(headers):
    """Returns encodings from given HTTP Header Dict.

    :param headers: dictionary to extract encoding from.
    """

    content_type = headers.get('content-type')

    if not content_type:
        return None

    content_type, params = cgi.parse_header(content_type)

    if 'charset' in params:
        return params['charset'].strip("'\"")

    if 'text' in content_type:
        return 'ISO-8859-1'


def stream_decode_response_unicode(iterator, r):
    """Stream decodes a iterator."""

    if r.encoding is None:
        for item in iterator:
            yield item
        return

    decoder = codecs.getincrementaldecoder(r.encoding)(errors='replace')
    for chunk in iterator:
        rv = decoder.decode(chunk)
        if rv:
            yield rv
    rv = decoder.decode('', final=True)
    if rv:
        yield rv


def get_unicode_from_response(r):
    """Returns the requested content back in unicode.

    :param r: Response object to get unicode content from.

    Tried:

    1. charset from content-type

    2. every encodings from ``<meta ... charset=XXX>``

    3. fall back and replace all unicode characters

    """

    tried_encodings = []

    # Try charset from content-type
    encoding = get_encoding_from_headers(r.headers)

    if encoding:
        try:
            return str(r.content, encoding)
        except UnicodeError:
            tried_encodings.append(encoding)

    # Fall back:
    try:
        return str(r.content, encoding, errors='replace')
    except TypeError:
        return r.content


def stream_decompress(iterator, mode='gzip'):
    """
    Stream decodes an iterator over compressed data

    :param iterator: An iterator over compressed data
    :param mode: 'gzip' or 'deflate'
    :return: An iterator over decompressed data
    """

    if mode not in ['gzip', 'deflate']:
        raise ValueError('stream_decompress mode must be gzip or deflate')

    zlib_mode = 16 + zlib.MAX_WBITS if mode == 'gzip' else -zlib.MAX_WBITS
    dec = zlib.decompressobj(zlib_mode)
    try:
        for chunk in iterator:
            rv = dec.decompress(chunk)
            if rv:
                yield rv
    except zlib.error:
        # If there was an error decompressing, just return the raw chunk
        yield chunk
        # Continue to return the rest of the raw data
        for chunk in iterator:
            yield chunk
    else:
        # Make sure everything has been returned from the decompression object
        buf = dec.decompress(bytes())
        rv = buf + dec.flush()
        if rv:
            yield rv


def stream_untransfer(gen, resp):
    if 'gzip' in resp.headers.get('content-encoding', ''):
        gen = stream_decompress(gen, mode='gzip')
    elif 'deflate' in resp.headers.get('content-encoding', ''):
        gen = stream_decompress(gen, mode='deflate')

    return gen


# The unreserved URI characters (RFC 3986)
UNRESERVED_SET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    + "0123456789-._~")


def unquote_unreserved(uri):
    """Un-escape any percent-escape sequences in a URI that are unreserved
    characters.
    This leaves all reserved, illegal and non-ASCII bytes encoded.
    """
    parts = uri.split('%')
    for i in range(1, len(parts)):
        h = parts[i][0:2]
        if len(h) == 2:
            c = chr(int(h, 16))
            if c in UNRESERVED_SET:
                parts[i] = c + parts[i][2:]
            else:
                parts[i] = '%' + parts[i]
        else:
            parts[i] = '%' + parts[i]
    return ''.join(parts)


def requote_uri(uri):
    """Re-quote the given URI.

    This function passes the given URI through an unquote/quote cycle to
    ensure that it is fully and consistently quoted.
    """
    # Unquote only the unreserved characters
    # Then quote only illegal characters (do not quote reserved, unreserved,
    # or '%')
    return quote(unquote_unreserved(uri), safe="!#$%&'()*+,/:;=?@[]~")
