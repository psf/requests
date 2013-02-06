# -*- coding: utf-8 -*-

"""
requests.utils
~~~~~~~~~~~~~~

This module provides utility functions that are used within Requests
that are also useful for external consumption.

"""

import cgi
import codecs
import os
import platform
import re
import sys
import zlib
from netrc import netrc, NetrcParseError

from . import __version__
from . import certs
from .compat import parse_http_list as _parse_list_header
from .compat import quote, urlparse, bytes, str, OrderedDict, urlunparse
from .cookies import RequestsCookieJar, cookiejar_from_dict

_hush_pyflakes = (RequestsCookieJar,)

NETRC_FILES = ('.netrc', '_netrc')

DEFAULT_CA_BUNDLE_PATH = certs.where()


def dict_to_sequence(d):
    """Returns an internal sequence dictionary update."""

    if hasattr(d, 'items'):
        d = d.items()

    return d


def super_len(o):
    if hasattr(o, '__len__'):
        return len(o)
    if hasattr(o, 'len'):
        return o.len
    if hasattr(o, 'fileno'):
        return os.fstat(o.fileno()).st_size


def get_netrc_auth(url):
    """Returns the Requests tuple auth for a given url from netrc."""

    try:
        locations = (os.path.expanduser('~/{0}'.format(f)) for f in NETRC_FILES)
        netrc_path = None

        for loc in locations:
            if os.path.exists(loc) and not netrc_path:
                netrc_path = loc

        # Abort early if there isn't one.
        if netrc_path is None:
            return netrc_path

        ri = urlparse(url)

        # Strip port numbers from netloc
        host = ri.netloc.split(':')[0]

        try:
            _netrc = netrc(netrc_path).authenticators(host)
            if _netrc:
                # Return with login / password
                login_i = (0 if _netrc[0] else 1)
                return (_netrc[login_i], _netrc[2])
        except (NetrcParseError, IOError):
            # If there was a parsing error or a permissions issue reading the file,
            # we'll just skip netrc auth
            pass

    # AppEngine hackiness.
    except (ImportError, AttributeError):
        pass


def guess_filename(obj):
    """Tries to guess the filename of the given object."""
    name = getattr(obj, 'name', None)
    if name and name[0] != '<' and name[-1] != '>':
        return os.path.basename(name)


def from_key_val_list(value):
    """Take an object and test to see if it can be represented as a
    dictionary. Unless it can not be represented as such, return an
    OrderedDict, e.g.,

    ::

        >>> from_key_val_list([('key', 'val')])
        OrderedDict([('key', 'val')])
        >>> from_key_val_list('string')
        ValueError: need more than 1 value to unpack
        >>> from_key_val_list({'key': 'val'})
        OrderedDict([('key', 'val')])
    """
    if value is None:
        return None

    if isinstance(value, (str, bytes, bool, int)):
        raise ValueError('cannot encode objects that are not 2-tuples')

    return OrderedDict(value)


def to_key_val_list(value):
    """Take an object and test to see if it can be represented as a
    dictionary. If it can be, return a list of tuples, e.g.,

    ::

        >>> to_key_val_list([('key', 'val')])
        [('key', 'val')]
        >>> to_key_val_list({'key': 'val'})
        [('key', 'val')]
        >>> to_key_val_list('string')
        ValueError: cannot encode objects that are not 2-tuples.
    """
    if value is None:
        return None

    if isinstance(value, (str, bytes, bool, int)):
        raise ValueError('cannot encode objects that are not 2-tuples')

    if isinstance(value, dict):
        value = value.items()

    return list(value)


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


def dict_from_cookiejar(cj):
    """Returns a key/value dictionary from a CookieJar.

    :param cj: CookieJar object to extract cookies from.
    """

    cookie_dict = {}

    for cookie in cj:
        cookie_dict[cookie.name] = cookie.value

    return cookie_dict


def add_dict_to_cookiejar(cj, cookie_dict):
    """Returns a CookieJar from a key/value dictionary.

    :param cj: CookieJar to insert cookies into.
    :param cookie_dict: Dict of key/values to insert into CookieJar.
    """

    cj2 = cookiejar_from_dict(cookie_dict)
    for cookie in cj2:
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


def iter_slices(string, slice_length):
    """Iterate over slices of a string."""
    pos = 0
    while pos < len(string):
        yield string[pos:pos + slice_length]
        pos += slice_length


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
    """Stream decodes an iterator over compressed data

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
    ce = resp.headers.get('content-encoding', '').lower()
    if 'gzip' in ce:
        gen = stream_decompress(gen, mode='gzip')
    elif 'deflate' in ce:
        gen = stream_decompress(gen, mode='deflate')

    return gen


# The unreserved URI characters (RFC 3986)
UNRESERVED_SET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    + "0123456789-._~")


def unquote_unreserved(uri):
    """Un-escape any percent-escape sequences in a URI that are unreserved
    characters. This leaves all reserved, illegal and non-ASCII bytes encoded.
    """
    parts = uri.split('%')
    for i in range(1, len(parts)):
        h = parts[i][0:2]
        if len(h) == 2 and h.isalnum():
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


def get_environ_proxies(url):
    """Return a dict of environment proxies."""

    proxy_keys = [
        'all',
        'http',
        'https',
        'ftp',
        'socks'
    ]

    get_proxy = lambda k: os.environ.get(k) or os.environ.get(k.upper())

    # First check whether no_proxy is defined. If it is, check that the URL
    # we're getting isn't in the no_proxy list.
    no_proxy = get_proxy('no_proxy')

    if no_proxy:
        # We need to check whether we match here. We need to see if we match
        # the end of the netloc, both with and without the port.
        no_proxy = no_proxy.split(',')
        netloc = urlparse(url).netloc

        for host in no_proxy:
            if netloc.endswith(host) or netloc.split(':')[0].endswith(host):
                # The URL does match something in no_proxy, so we don't want
                # to apply the proxies on this URL.
                return {}

    # If we get here, we either didn't have no_proxy set or we're not going
    # anywhere that no_proxy applies to.
    proxies = [(key, get_proxy(key + '_proxy')) for key in proxy_keys]
    return dict([(key, val) for (key, val) in proxies if val])


def default_user_agent():
    """Return a string representing the default user agent."""
    _implementation = platform.python_implementation()

    if _implementation == 'CPython':
        _implementation_version = platform.python_version()
    elif _implementation == 'PyPy':
        _implementation_version = '%s.%s.%s' % (sys.pypy_version_info.major,
                                                sys.pypy_version_info.minor,
                                                sys.pypy_version_info.micro)
        if sys.pypy_version_info.releaselevel != 'final':
            _implementation_version = ''.join([_implementation_version, sys.pypy_version_info.releaselevel])
    elif _implementation == 'Jython':
        _implementation_version = platform.python_version()  # Complete Guess
    elif _implementation == 'IronPython':
        _implementation_version = platform.python_version()  # Complete Guess
    else:
        _implementation_version = 'Unknown'

    try:
        p_system = platform.system()
        p_release = platform.release()
    except IOError:
        p_system = 'Unknown'
        p_release = 'Unknown'

    return " ".join(['python-requests/%s' % __version__,
                     '%s/%s' % (_implementation, _implementation_version),
                     '%s/%s' % (p_system, p_release)])


def default_headers():
    return {
        'User-Agent': default_user_agent(),
        'Accept-Encoding': ', '.join(('gzip', 'deflate', 'compress')),
        'Accept': '*/*'
    }


def parse_header_links(value):
    """Return a dict of parsed link headers proxies.

    i.e. Link: <http:/.../front.jpeg>; rel=front; type="image/jpeg",<http://.../back.jpeg>; rel=back;type="image/jpeg"

    """

    links = []

    replace_chars = " '\""

    for val in value.split(","):
        try:
            url, params = val.split(";", 1)
        except ValueError:
            url, params = val, ''

        link = {}

        link["url"] = url.strip("<> '\"")

        for param in params.split(";"):
            try:
                key, value = param.split("=")
            except ValueError:
                break

            link[key.strip(replace_chars)] = value.strip(replace_chars)

        links.append(link)

    return links


# Null bytes; no need to recreate these on each call to guess_json_utf
_null = '\x00'.encode('ascii')  # encoding to ASCII for Python 3
_null2 = _null * 2
_null3 = _null * 3


def guess_json_utf(data):
    # JSON always starts with two ASCII characters, so detection is as
    # easy as counting the nulls and from their location and count
    # determine the encoding. Also detect a BOM, if present.
    sample = data[:4]
    if sample in (codecs.BOM_UTF32_LE, codecs.BOM32_BE):
        return 'utf-32'     # BOM included
    if sample[:3] == codecs.BOM_UTF8:
        return 'utf-8-sig'  # BOM included, MS style (discouraged)
    if sample[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        return 'utf-16'     # BOM included
    nullcount = sample.count(_null)
    if nullcount == 0:
        return 'utf-8'
    if nullcount == 2:
        if sample[::2] == _null2:   # 1st and 3rd are null
            return 'utf-16-be'
        if sample[1::2] == _null2:  # 2nd and 4th are null
            return 'utf-16-le'
        # Did not detect 2 valid UTF-16 ascii-range characters
    if nullcount == 3:
        if sample[:3] == _null3:
            return 'utf-32-be'
        if sample[1:] == _null3:
            return 'utf-32-le'
        # Did not detect a valid UTF-32 ascii-range character
    return None


def prepend_scheme_if_needed(url, new_scheme):
    '''Given a URL that may or may not have a scheme, prepend the given scheme.
    Does not replace a present scheme with the one provided as an argument.'''
    scheme, netloc, path, params, query, fragment = urlparse(url, new_scheme)

    # urlparse is a finicky beast, and sometimes decides that there isn't a
    # netloc present. Assume that it's being over-cautious, and switch netloc
    # and path if urlparse decided there was no netloc.
    if not netloc:
        netloc, path = path, netloc

    return urlunparse((scheme, netloc, path, params, query, fragment))


def get_auth_from_url(url):
    """Given a url with authentication components, extract them into a tuple of
    username,password."""
    if url:
        parsed = urlparse(url)
        return (parsed.username, parsed.password)
    else:
        return ('', '')
