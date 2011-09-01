# -*- coding: utf-8 -*-

"""
requests.hooks
~~~~~~~~~~~~~~

This module provides the capabilities for the Requests hooks system.

Available hooks:

``args``:
    A dictionary of the arguments being sent to Request().

``pre_request``:
    The Request object, directly before being sent.

``post_request``:
    The Request object, directly after being sent.

``response``:
    The response generated from a Request.

"""

import warnings
from collections import Iterable
import config
import zlib
import bz2
from cgi import parse_header

def setup_hooks(supplied):
    """Setup a hooks mapping, based on the supplied argument. Eache mapping
    value will be list of hooks that will extend the **default_hooks**.

    :param supplied: a dictionary of hooks. Each value can either be a callable
                     or a list of callables.
    :type supplied: dict
    :returns: a dictionary of hooks that extends the **default_hooks** dictionary.
    :rtype: dict
    """

    # Copy the default hooks settings.
    default = config.settings.default_hooks
    dispatching = dict([(k, v[:]) for k, v in default.items()])

    # I abandoned the idea of a dictionary of sets because sets may not keep
    # insertion order, while it may be important. Also, there is no real reason
    # to force hooks to run once.
    for hooks, values in supplied.items():
        hook_list = values if isinstance(values, Iterable) else [values]
        dispatching[hooks].extend(hook_list)

    # If header is set by config, maybe response is encoded.
    if config.settings.base_headers.get('Accept-Encoding', ''):
        if not decode_encoding in dispatching['response']:
            # It's safer to put decoding as first hook.
            dispatching['response'].insert(0, decode_encoding)

    if config.settings.decode_unicode:
        try:
            # Try unicode encoding just after content decoding...
            index = dispatching['response'].index(decode_encoding) + 1
        except ValueError:
            # ... Or as first hook
            index = 0
        dispatching['response'].insert(index, decode_unicode)

    return dispatching

def dispatch_hooks(hooks, data):
    """Dispatches multiple hooks on a given piece of data.

    :param key: the hooks group to lookup
    :type key: str
    :param hooks: the hooks dictionary. The value of each key can be a callable
                  object, or a list of callable objects.
    :type hooks: dict
    :param data: the object on witch the hooks should be applied
    :type data: object
    """
    for hook in hooks:
        try:
            # hook must be a callable.
            data = hook(data)

        except Exception, why:

            # Letting users to choose a policy may be an idea. It can be as
            # simple as "be gracefull, or not":
            #
            # config.settings.gracefull_hooks = True | False
            if not config.settings.gracefull_hooks: raise

            warnings.warn(str(why))

    return data

#: Example response hook that turns a JSON formatted
#: :py:class:`requests.models.Response.content` into a dumped data structure::
#:
#:    try:
#:        import json
#:    except ImportError:
#:        try:
#:            import simplejson as json
#:        except ImportError:
#:            json = False
#:
#:    if json:
#:        def json_content(r):
#:            """Turns content into a dumped JSON structure."""
#:            r._content = json.dumps(r.content)
#:            return r
#:
#: Example response hook that turns an XML formatted
#: :py:class:`requests.models.Response.content` into an ElementTree::
#:
#:    try:
#:        from lxml import etree
#:    except ImportError:
#:        try:
#:            import xml.etree.cElementTree as etree
#:        except ImportError:
#:            try:
#:                import xml.etree.ElementTree as etree
#:            except ImportError:
#:                try:
#:                    import cElementTree as etree
#:                except ImportError:
#:                    try:
#:                        import elementtree.ElementTree as etree
#:                    except ImportError:
#:                        etree = False
#:
#:    if etree:
#:        def etree_content(r):
#:            """Turns content into an ElementTree structure."""
#:            r._content = etree.fromstring(r.content)
#:            return r

def decode_unicode(r):
    """Encode content into unicode string.

       :param r: response object
       :type r: :py:class:`requests.models.Response`
       :returns: the same input object.
       :rtype: :py:class:`requests.models.Response`
    """
    content_type, params = parse_header(r.headers['content-type'])
    charset = params.get('charset', '').strip("'\"")
    r._content = unicode(r.content, charset) if charset else unicode(r.content)
    return r

def decode_encoding(r):
    """Decode content using Contetn-Encoding header.

       :param r: response object
       :type r: :py:class:`requests.models.Response`
       :returns: the same input object.
       :rtype: :py:class:`requests.models.Response`
    """

    # Dictionary of content decoders.
    decode = {
        # No decoding applied.
        'identity': lambda content: content,
        # Decode Response content compressed with deflate.
        'deflate': lambda content: zlib.decompress(content),
        # Decode Response content compressed with gzip.
        'gzip': lambda content: zlib.decompress(content, 16+zlib.MAX_WBITS),
        # Decode Response content compressed with bz2.
        # Not a standard Content-Encoding value, but..
        'bzip2': lambda content: bz2.decompress(content),
    }
    # Decode Response content compressed with compress.
    # If I understood zlib...
    decode['compress'] = decode['deflate']

    # Apply decoding only if the header is set.
    encoding = r.headers['content-encoding']
    if encoding:
        r._content = decode[encoding](r.content)
    return r
