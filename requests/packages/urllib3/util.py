# urllib3/util.py
# Copyright 2008-2012 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php


from base64 import b64encode

try:
    from select import poll, POLLIN
except ImportError: # `poll` doesn't exist on OSX and other platforms
    poll = False
    try:
        from select import select
    except ImportError: # `select` doesn't exist on AppEngine.
        select = False

from .packages import six
from .exceptions import LocationParseError


def make_headers(keep_alive=None, accept_encoding=None, user_agent=None,
                 basic_auth=None):
    """
    Shortcuts for generating request headers.

    :param keep_alive:
        If ``True``, adds 'connection: keep-alive' header.

    :param accept_encoding:
        Can be a boolean, list, or string.
        ``True`` translates to 'gzip,deflate'.
        List will get joined by comma.
        String will be used as provided.

    :param user_agent:
        String representing the user-agent you want, such as
        "python-urllib3/0.6"

    :param basic_auth:
        Colon-separated username:password string for 'authorization: basic ...'
        auth header.

    Example: ::

        >>> make_headers(keep_alive=True, user_agent="Batman/1.0")
        {'connection': 'keep-alive', 'user-agent': 'Batman/1.0'}
        >>> make_headers(accept_encoding=True)
        {'accept-encoding': 'gzip,deflate'}
    """
    headers = {}
    if accept_encoding:
        if isinstance(accept_encoding, str):
            pass
        elif isinstance(accept_encoding, list):
            accept_encoding = ','.join(accept_encoding)
        else:
            accept_encoding = 'gzip,deflate'
        headers['accept-encoding'] = accept_encoding

    if user_agent:
        headers['user-agent'] = user_agent

    if keep_alive:
        headers['connection'] = 'keep-alive'

    if basic_auth:
        headers['authorization'] = 'Basic ' + \
            b64encode(six.b(basic_auth)).decode('utf-8')

    return headers


def split_first(s, delims):
    """
    Given a string and an iterable of delimiters, split on the first found
    delimiter. Return two split parts.

    If not found, then the first part is the full input string.

    Scales linearly with number of delims. Not ideal for large number of delims.
    """
    min_idx = None
    for d in delims:
        idx = s.find(d)
        if idx < 0:
            continue

        if not min_idx:
            min_idx = idx
        else:
            min_idx = min(idx, min_idx)

    if min_idx < 0:
        return s, ''

    return s[:min_idx], s[min_idx+1:]


def get_host(url):
    """
    Given a url, return its scheme, host and port (None if it's not there).

    For example: ::

        >>> get_host('http://google.com/mail/')
        ('http', 'google.com', None)
        >>> get_host('google.com:80')
        ('http', 'google.com', 80)
    """

    # While this code has overlap with stdlib's urlparse, it is much
    # simplified for our needs and less annoying.
    # Additionally, this imeplementations does silly things to be optimal
    # on CPython.

    scheme = 'http'
    host = None
    port = None

    # Scheme
    if '://' in url:
        scheme, url = url.split('://', 1)

    # Find the earliest Authority Terminator
    # (http://tools.ietf.org/html/rfc3986#section-3.2)
    url, _path = split_first(url, ['/', '?', '#'])

    # Auth
    if '@' in url:
        _auth, url = url.split('@', 1)

    # IPv6
    if url and url[0] == '[':
        host, url = url[1:].split(']', 1)

    # Port
    if ':' in url:
        _host, port = url.split(':', 1)

        if not host:
            host = _host

        if not port.isdigit():
            raise LocationParseError("Failed to parse: %s" % url)

        port = int(port)

    elif not host:
        host = url

    return scheme, host, port


def is_connection_dropped(conn):
    """
    Returns True if the connection is dropped and should be closed.

    :param conn:
        ``HTTPConnection`` object.

    Note: For platforms like AppEngine, this will always return ``False`` to
    let the platform handle connection recycling transparently for us.
    """
    sock = getattr(conn, 'sock', False)
    if not sock: # Platform-specific: AppEngine
        return False

    if not poll: # Platform-specific
        if not select: # Platform-specific: AppEngine
            return False

        return select([sock], [], [], 0.0)[0]

    # This version is better on platforms that support it.
    p = poll()
    p.register(sock, POLLIN)
    for (fno, ev) in p.poll(0.0):
        if fno == sock.fileno():
            # Either data is buffered (bad), or the connection is dropped.
            return True
