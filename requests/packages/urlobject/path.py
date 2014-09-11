# -*- coding: utf-8 -*-

import posixpath
import urllib

from .compat import urlparse
from .six import text_type, u


class Root(object):

    """A descriptor which always returns the root path."""

    def __get__(self, instance, cls):
        return cls('/')


class URLPath(text_type):

    root = Root()

    def __repr__(self):
        return u('URLPath(%r)') % (text_type(self),)

    @classmethod
    def join_segments(cls, segments, absolute=True):
        """Create a :class:`URLPath` from an iterable of segments."""
        if absolute:
            path = cls('/')
        else:
            path = cls('')
        for segment in segments:
            path = path.add_segment(segment)
        return path

    @property
    def segments(self):
        """
        Split this path into (decoded) segments.

            >>> URLPath('/a/b/c').segments
            ('a', 'b', 'c')

        Non-leaf nodes will have a trailing empty string, and percent encodes
        will be decoded:

            >>> URLPath('/a%20b/c%20d/').segments
            ('a b', 'c d', '')
        """
        segments = tuple(map(path_decode, self.split('/')))
        if segments[0] == '':
            return segments[1:]
        return segments

    @property
    def parent(self):
        """
        The parent of this node.

            >>> URLPath('/a/b/c').parent
            URLPath('/a/b/')
            >>> URLPath('/foo/bar/').parent
            URLPath('/foo/')
        """
        if self.is_leaf:
            return self.relative('.')
        return self.relative('..')

    @property
    def is_leaf(self):
        """
        Is this path a leaf node?

            >>> URLPath('/a/b/c').is_leaf
            True
            >>> URLPath('/a/b/').is_leaf
            False
        """
        return self and self.segments[-1] != '' or False

    @property
    def is_relative(self):
        """
        Is this path relative?

            >>> URLPath('a/b/c').is_relative
            True
            >>> URLPath('/a/b/c').is_relative
            False
        """
        return self[0] != '/'

    @property
    def is_absolute(self):
        """
        Is this path absolute?

            >>> URLPath('a/b/c').is_absolute
            False
            >>> URLPath('/a/b/c').is_absolute
            True
        """
        return self[0] == '/'

    def relative(self, rel_path):
        """
        Resolve a relative path against this one.

            >>> URLPath('/a/b/c').relative('.')
            URLPath('/a/b/')
            >>> URLPath('/a/b/c').relative('d')
            URLPath('/a/b/d')
            >>> URLPath('/a/b/c').relative('../d')
            URLPath('/a/d')
        """
        return type(self)(urlparse.urljoin(self, rel_path))

    def add_segment(self, segment):
        """
        Add a segment to this path.

            >>> URLPath('/a/b/').add_segment('c')
            URLPath('/a/b/c')

        Non-ASCII and reserved characters (including slashes) will be encoded:

            >>> URLPath('/a/b/').add_segment('dé/f')
            URLPath('/a/b/d%C3%A9%2Ff')
        """
        return type(self)(posixpath.join(self, path_encode(segment)))

    def add(self, path):
        """
        Add a partial path to this one.

        The only difference between this and :meth:`add_segment` is that slash
        characters will not be encoded, making it suitable for adding more than
        one path segment at a time:

            >>> URLPath('/a/b/').add('dé/f/g')
            URLPath('/a/b/d%C3%A9/f/g')
        """
        return type(self)(posixpath.join(self, path_encode(path, safe='/')))


def _path_encode_py2(s, safe=''):
    """Quote unicode or str using path rules."""
    if isinstance(s, unicode):
        s = s.encode('utf-8')
    if isinstance(safe, unicode):
        safe = safe.encode('utf-8')
    return urllib.quote(s, safe=safe).decode('utf-8')


def _path_encode_py3(s, safe=''):
    """Quote str or bytes using path rules."""
    # s can be bytes or unicode, urllib.parse.quote() assumes
    # utf-8 if encoding is necessary.
    return urlparse.quote(s, safe=safe)


def _path_decode_py2(s):
    """Unquote unicode or str using path rules."""
    if isinstance(s, unicode):
        s = s.encode('utf-8')
    return urllib.unquote(s).decode('utf-8')


def _path_decode_py3(s):
    """Unquote str or bytes using path rules."""
    if isinstance(s, bytes):
        s = s.decode('utf-8')
    return urlparse.unquote(s)


if hasattr(urllib, 'quote'):
    path_encode = _path_encode_py2
    path_decode = _path_decode_py2
    del _path_encode_py3
    del _path_decode_py3
else:
    path_encode = _path_encode_py3
    path_decode = _path_decode_py3
    del _path_encode_py2
    del _path_decode_py2
