"""
request.hooks.response
~~~~~~~~~~~~~~~~~~~~~~

This module provide a collection of response hooks.
"""
import zlib
import bz2
from cgi import parse_header

try:
    import json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        json = False
try:
    from lxml import etree
except ImportError:
    try:
        import xml.etree.cElementTree as etree
    except ImportError:
        try:
            import xml.etree.ElementTree as etree
        except ImportError:
            try:
                import cElementTree as etree
            except ImportError:
                try:
                    import elementtree.ElementTree as etree
                except ImportError:
                    etree = False

#: Dictionary of content decoders.
content_decoders = {
    # No decoding applied.
    'identity': lambda content: content,
    # Decode Response file object compressed with deflate.
    'deflate': lambda content: zlib.decompress(content),
    # Decode Response file object compressed with gzip.
    'gzip': lambda content: zlib.decompress(content, 16+zlib.MAX_WBITS),
    # Decode Response file object compressed with bz2.
    # Not a standard Content-Encoding value, but..
    'bzip2': lambda content: bz2.decompress(content),
}

# Decode Response file object compressed with compress.
content_decoders['compress'] = content_decoders['deflate']

def decode_unicode(r):
    """Encode a :py:class:`requests.models.Response` file object in unicode."""
    content_type, params = parse_header(r.headers['content-type'])
    charset = params.get('charset', '').strip("'\"")
    r._content = unicode(r.content, charset) if charset else unicode(r.content)
    return r

def decode_encoding(r):
    """
        Decode a :py:class:`requests.models.Response` content using
        Contetn-Encoding header.
    """
    # Apply decoding only if the header is set.
    encoding = r.headers['content-encoding']
    if encoding:
        r._content = content_decoders[encoding](r.content)
    return r

if json:
    def json_content(r):
        """
            Turns :py:class:`requests.models.Response` content into a dumped
            JSON structure.
        """
        r._content = json.dumps(r.content)
        return r

if etree:
    def etree_content(r):
        """
            Turns :py:class:`requests.models.Response` content into an
            ElementTree structure.
        """
        r._content = etree.fromstring(r.content)
        return r
