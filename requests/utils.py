# -*- coding: utf-8 -*-

"""
requests.utils
~~~~~~~~~~~~~~

This module provides utlity functions that are used within Requests
that are also useful for external consumption.

"""

import cgi
import codecs
import cookielib
import re
import urllib
import zlib
from urlparse import urlparse, urlunparse, urljoin


def encode_params(params):
    """Encode parameters in a piece of data.

    If the data supplied is a dictionary, encodes each parameter in it, and
    returns a list of tuples containing the encoded parameters, and a urlencoded
    version of that.

    Otherwise, assumes the data is already encoded appropriately, and
    returns it twice.
    """

    if hasattr(params, 'items'):
        result = []
        for k, vs in params.items():
            for v in isinstance(vs, list) and vs or [vs]:
                result.append(
                    (
                        k.encode('utf-8') if isinstance(k, unicode) else k,
                        v.encode('utf-8') if isinstance(v, unicode) else v
                    )
                )
        return urllib.urlencode(result, doseq=True)

    else:
        return params

def get_clean_url(url, parent_url=None):
    # Handle redirection without scheme (see: RFC 1808 Section 4)
    if url.startswith('//'):
        parsed_rurl = urlparse(parent_url)
        url = '%s:%s' % (parsed_rurl.scheme, url)

    scheme, netloc, path, params, query, fragment = urlparse(url)
    if netloc:
        netloc = netloc.encode('idna')

    if isinstance(path, unicode):
        path = path.encode('utf-8')

    path = urllib.quote(path, safe="%/:=&?~#+!$,;'@()*[]")
    params = urllib.quote(params, safe="%/:=&?~#+!$,;'@()*[]")
    query = urllib.quote(query, safe="%/:=&?~#+!$,;'@()*[]")

    url = str(urlunparse([scheme, netloc, path, params, query, fragment]))

    # Facilitate non-RFC2616-compliant 'location' headers
    # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
    if not netloc and parent_url:
        url = urljoin(parent_url, url)

    return url

def build_url(url, query_params):
    """Build the actual URL to use."""

    url = get_clean_url(url)

    query_params = encode_params(query_params)

    if query_params:
       if urlparse(url).query:
           return '%s&%s' % (url, query_params)
       else:
           return '%s?%s' % (url, query_params)
    else:
       return url

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
        headers = headers.items()

    elif isinstance(headers, basestring):
        return headers

    for i, (value, params) in enumerate(headers):

        _params = []

        for (p_k, p_v) in params.items():

            _params.append('%s=%s' % (p_k, p_v))

        collector.append(value)
        collector.append('; ')

        if len(params):

            collector.append('; '.join(_params))

        if not len(headers) == i + 1:
                collector.append(', ')

    # Remove trailing seperators.
    if collector[-1] in (', ', '; '):
        del collector[-1]

    return ''.join(collector)


def dict_from_cookiejar(cookies):
    """Returns a key/value dictionary from a CookieJar.

    :param cj: CookieJar object to extract cookies from.
    """

    cookie_dict = {}

    for _, cookies in cookies.items():
        for _, cookies in cookies.items():
            for cookie in cookies.values():
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

    for k, v in cookie_dict.items():

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


def unicode_from_html(content):
    """Attempts to decode an HTML string into unicode.
    If unsuccessful, the original content is returned.
    """

    encodings = get_encodings_from_content(content)

    for encoding in encodings:

        try:
            return unicode(content, encoding)
        except (UnicodeError, TypeError):
            pass

        return content


def stream_decode_response_unicode(iterator, r):
    """Stream decodes a iterator."""
    encoding = get_encoding_from_headers(r.headers)
    try:
        decoder = codecs.getincrementaldecoder(str(encoding))(errors='replace')
    except LookupError:
        for item in iterator:
            yield item
        return
    for chunk in iterator:
        rv = decoder.decode(chunk)
        if rv:
            yield rv
    rv = decoder.decode('', final=True)
    if rv:
        yield rv


def get_unicode_from_response(r):
    """Returns the requested content back in unicode.

    :param r: Reponse object to get unicode content from.

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
            return unicode(r.content, encoding)
        except UnicodeError:
            tried_encodings.append(encoding)
        except LookupError:
            return r.content

    # Fall back:
    try:
        return unicode(r.content, encoding, errors='replace')
    except TypeError:
        return r.content


def decode_gzip(content):
    """Return gzip-decoded string.

    :param content: bytestring to gzip-decode.
    """

    return zlib.decompress(content, 16 + zlib.MAX_WBITS)
    return zlib.decompress(content, 16 + zlib.MAX_WBITS)
    return zlib.decompress(content, 16 + zlib.MAX_WBITS)


def stream_decode_gzip(iterator):
    """Stream decodes a gzip-encoded iterator"""
    try:
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        for chunk in iterator:
            rv = dec.decompress(chunk)
            if rv:
                yield rv
        buf = dec.decompress('')
        rv = buf + dec.flush()
        if rv:
            yield rv
    except zlib.error:
        pass


def curl_from_request(request):
    """Returns a curl command from the request.

    :param request: The :class:`Request <Request>` object

    Example:
        | import requests
        | from requests.utils import curl_from_request
        | r = requests.get('http://httpbin.org/get')
        | curl_from_request(r.request)

    """

    #TODO - OAuth

    #: -L/--location - if there is a redirect, redo request on the new place.
    curl = 'curl -L '

    #: -u/--user - Specify the user name and password to use for server auth.
    #: Basic Auth only for now
    auth = ''

    if request.auth is not None:

        auth = '-u "%s:%s" ' % (request.auth.username, request.auth.password)

    method = ''

    if request.method.upper() == 'HEAD':
        #: -I/--head - fetch headers only.
        method = '-I '
    else:
        #: -X/--request - specify request method.
        method = '-X %s ' % request.method.upper()

    #: -b/--cookie
    #: (HTTP) Pass the data to the HTTP server as a cookie. It is supposedly the
    #: data previously received from the server in a "Set-Cookie:" line.
    cookies = ''
    if request.cookiejar:
        cookies = cookies.join(['-b "%s=%s" ' % (k.name, k.value) for k in request.cookiejar])

    #: -H/--header - Extra header to use when getting a web page.
    header = ''
    if request.headers:
        header = header.join(['-H "%s:%s" ' % (k, v) for k, v in request.headers.iteritems()])

    form = ''
    if request.method in ('PUT', 'POST', 'PATCH'):
        #: request.files is updated with request.data if both exist, so only iterate request.files.
        #: ContentType multipart/form-data is used.
        if request.files:
           #: -F/--form - Emulate form data. To force 'content' to a file, prefix file name @.
            for k, v in request.files.iteritems():
                if isinstance(v, file):
                    form = form + '-F "%s=@%s" ' % (k, v.name)
                elif v not in (None, ''):
                    form = form + '-F "%s=%s" ' % (k, v)

        #: content-type application/x-www-form-urlencoded is used here.
        else:
            #: -d/--data - send specified data in post request.
            if isinstance(request.data, (list, tuple)):
                form = form.join(['-d "%s=%s" ' % (k, v) for k, v in request.data])
            elif request._enc_data not in (None, ''):
                form = "-d '%s' " % (request._enc_data)

    #: Params handled in _build_url
    return curl + auth + method + header + cookies + form + '"' + request._build_url() + '"'
