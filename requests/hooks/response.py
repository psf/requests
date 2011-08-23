"""
request.hooks.response
~~~~~~~~~~~~~~~~~~~~~~

This module provide a collection of response hooks.
"""
from functools import wraps
import zlib
from cgi import parse_header

#: Dictionary of content decoders.
decoders = {
    # No decoding applied.
    'identity': lambda r: r,
    # Decode Response file object compressed with deflate.
    'deflate': lambda r: zlib.decompress(r.content),
    # Decode Response file object compressed with gzip.
    'gzip': lambda r: zlib.decompress(r.content, 16+zlib.MAX_WBITS),
}

# Decode Response file object compressed with compress.
decoders['compress'] = decoders['deflate']

try:
    import bz2
except ImportError:
    pass
else:
    # Decode Response file object compressed with bz2.
    decoders['bzip2'] = lambda r: bz2.decompress(r.content)

def unicode_response(r):
    """Encode response file object in unicode."""
    content_type, params = parse_header(r.headers.get('content-type'))
    charset = params.get('charset', '').strip("'\"")
    r.content = unicode(r.content, charset) if charset else unicode(r.content)
    return r

def decode_response(r):
    """Decode compressed response content using Contetn-Encoding header."""
    encoding = r.headers.get('content-encoding')
    return decoders.get(encoding)(r)

