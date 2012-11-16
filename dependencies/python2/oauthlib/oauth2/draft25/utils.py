"""
oauthlib.utils
~~~~~~~~~~~~~~

This module contains utility methods used by various parts of the OAuth 2 spec.
"""

import urllib
import urlparse


def host_from_uri(uri):
    """Extract hostname and port from URI.

    Will use default port for HTTP and HTTPS if none is present in the URI.
    """
    default_ports = {
        u'HTTP': u'80',
        u'HTTPS': u'443',
    }

    sch, netloc, path, par, query, fra = urlparse.urlparse(uri)
    if u':' in netloc:
        netloc, port = netloc.split(u':', 1)
    else:
        port = default_ports.get(sch.upper())

    return netloc, port


def escape(u):
    """Escape a string in an OAuth-compatible fashion.

    TODO: verify whether this can in fact be used for OAuth 2

    """
    if not isinstance(u, unicode):
        raise ValueError('Only unicode objects are escapable.')
    return urllib.quote(u.encode('utf-8'), safe='~')
