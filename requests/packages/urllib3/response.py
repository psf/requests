import zlib
import io
from yieldfrom.http.client import HTTPResponse as _HTTPResponse

from ._collections import HTTPHeaderDict
from .exceptions import ProtocolError, DecodeError, ReadTimeoutError
from .packages.six import string_types as basestring, binary_type
from .connection import HTTPException, BaseSSLError

import asyncio


class DeflateDecoder(object):

    def __init__(self):
        self._first_try = True
        self._data = binary_type()
        self._obj = zlib.decompressobj()

    def __getattr__(self, name):
        return getattr(self._obj, name)

    def decompress(self, data):
        if not self._first_try:
            return self._obj.decompress(data)

        self._data += data
        try:
            return self._obj.decompress(data)
        except zlib.error:
            self._first_try = False
            self._obj = zlib.decompressobj(-zlib.MAX_WBITS)
            try:
                return self.decompress(self._data)
            finally:
                self._data = None


def _get_decoder(mode):
    if mode == 'gzip':
        return zlib.decompressobj(16 + zlib.MAX_WBITS)

    return DeflateDecoder()


class HTTPResponse(io.IOBase):
    """
    HTTP Response container.

    ### body is the original HTTPResponse

    Backwards-compatible to httplib's HTTPResponse but the response ``body`` is
    loaded and decoded on-demand when the ``data`` property is accessed.  This
    class is also compatible with the Python standard library's :mod:`io`
    module, and can hence be treated as a readable object in the context of that
    framework.

    Extra parameters for behaviour not present in httplib.HTTPResponse:

    :param preload_content:
        If True, the response's body will be preloaded during construction.

    :param decode_content:
        If True, attempts to decode specific content-encoding's based on headers
        (like 'gzip' and 'deflate') will be skipped and raw data will be used
        instead.

    :param original_response:
        When this HTTPResponse wrapper is generated from an httplib.HTTPResponse
        object, it's convenient to include the original for debug purposes. It's
        otherwise unused.
    """

    CONTENT_DECODERS = ['gzip', 'deflate']
    REDIRECT_STATUSES = [301, 302, 303, 307, 308]

    def __init__(self, body='', headers=None, status=0, version=0, reason=None,
                 strict=0, preload_content=True, decode_content=True,
                 original_response=None, pool=None, connection=None):

        self.headers = HTTPHeaderDict()
        if headers:
            self.headers.update(headers)
        self.status = status
        self.version = version
        self.reason = reason
        self.strict = strict
        self.decode_content = decode_content
        self.preload_content = preload_content

        self._decoder = None
        self._body = None
        self._fp = None
        self._original_response = original_response
        self._fp_bytes_read = 0

        if body:
            if isinstance(body, (basestring, binary_type)):
                self._body = body

            #elif isinstance(body, _HTTPResponse):
            #    self._fp = body.fp

            elif hasattr(body, 'read'):
                self._fp = body

        self._pool = pool
        self._connection = connection


    @asyncio.coroutine
    def init(self):
        if self.preload_content and not self._body:
            self._body = yield from self.read(decode_content=self.decode_content)

    def get_redirect_location(self):
        """
        Should we redirect and where to?

        :returns: Truthy redirect location string if we got a redirect status
            code and valid location. ``None`` if redirect status and no
            location. ``False`` if not a redirect status code.
        """
        if self.status in self.REDIRECT_STATUSES:
            return self.headers.get('location')

        return False

    def release_conn(self):
        if not self._pool or not self._connection:
            return

        self._pool._put_conn(self._connection)
        self._connection = None

    @property
    @asyncio.coroutine
    def data(self):
        # For backwords-compat with earlier urllib3 0.4 and earlier.
        if self._body:
            return self._body

        if self._fp:
            _d = yield from self.read(cache_content=True)
            return _d

    def tell(self):
        """
        Obtain the number of bytes pulled over the wire so far. May differ from
        the amount of content returned by :meth:``HTTPResponse.read`` if bytes
        are encoded on the wire (e.g, compressed).
        """
        return self._fp_bytes_read

    @asyncio.coroutine
    def read(self, amt=None, decode_content=None, cache_content=False):
        """
        Similar to :meth:`httplib.HTTPResponse.read`, but with two additional
        parameters: ``decode_content`` and ``cache_content``.

        :param amt:
            How much of the content to read. If specified, caching is skipped
            because it doesn't make sense to cache partial content as the full
            response.

        :param decode_content:
            If True, will attempt to decode the body based on the
            'content-encoding' header.

        :param cache_content:
            If True, will save the returned data such that the same result is
            returned despite of the state of the underlying file object. This
            is useful if you want the ``.data`` property to continue working
            after having ``.read()`` the file object. (Overridden if ``amt`` is
            set.)
        """
        # Note: content-encoding value should be case-insensitive, per RFC 7230
        # Section 3.2
        content_encoding = self.headers.get('content-encoding', '').lower()
        if self._decoder is None:
            if content_encoding in self.CONTENT_DECODERS:
                self._decoder = _get_decoder(content_encoding)
        if decode_content is None:
            decode_content = self.decode_content

        if self._fp is None:
            return

        flush_decoder = False

        try:
            try:
                if amt is None:
                    # cStringIO doesn't like amt=None
                    data = yield from self._fp.read()
                    flush_decoder = True
                else:
                    cache_content = False
                    data = yield from self._fp.read(amt)
                    if amt != 0 and not data:  # Platform-specific: Buggy versions of Python.
                        # Close the connection when no data is returned
                        #
                        # This is redundant to what httplib/http.client _should_
                        # already do.  However, versions of python released before
                        # December 15, 2012 (http://bugs.python.org/issue16298) do
                        # not properly close the connection in all cases. There is
                        # no harm in redundantly calling close.
                        self._fp.close()
                        flush_decoder = True

            except asyncio.TimeoutError:
                # FIXME: Ideally we'd like to include the url in the ReadTimeoutError but
                # there is yet no clean way to get at it from this context.
                raise ReadTimeoutError(self._pool, None, 'Read timed out.')

            except BaseSSLError as e:
                # FIXME: Is there a better way to differentiate between SSLErrors?
                if not 'read operation timed out' in str(e):  # Defensive:
                    # This shouldn't happen but just in case we're missing an edge
                    # case, let's avoid swallowing SSL errors.
                    raise

                raise ReadTimeoutError(self._pool, None, 'Read timed out.')

            except HTTPException as e:
                # This includes IncompleteRead.
                raise ProtocolError('Connection broken: %r' % e, e)

            self._fp_bytes_read += len(data)

            try:
                if decode_content and self._decoder:
                    data = self._decoder.decompress(data)
            except (IOError, zlib.error) as e:
                raise DecodeError(
                    "Received response with content-encoding: %s, but "
                    "failed to decode it." % content_encoding, e)

            if flush_decoder and decode_content and self._decoder:
                buf = self._decoder.decompress(binary_type())
                data += buf + self._decoder.flush()

            if cache_content:
                self._body = data

            return data

        finally:
            if self._original_response and self._original_response.isclosed():
                self.release_conn()

    @asyncio.coroutine
    def stream(self, amt=2**16, decode_content=None):
        """
        The original urllib3 has this as a generator, and feeds blocks
        on the fly.

        The use of coroutines for data reading blocks that usage, as
        the same method cannot be both a coroutine and an iterator. So
        this now just slurps the whole page, splits into blocks of the
        desired size, and returns an iterable (a list) of the blocks.

        So you can write similar usage:

        for block in (yield from resp.stream):
          # do something with block

        :param amt:
            How much of the content to read. The generator will return up to
            much data per iteration, but may return less. This is particularly
            likely when using compressed data. However, the empty string will
            never be returned.

        :param decode_content:
            If True, will attempt to decode the body based on the
            'content-encoding' header.
        """
        allData = yield from self.read(decode_content=decode_content)

        dataBlocks = []
        while allData:
            block = allData[:amt]
            dataBlocks.append(block)
            allData = allData[amt:]

        return iter(dataBlocks)

    @classmethod
    @asyncio.coroutine
    def from_httplib(ResponseCls, r, **response_kw):
        """
        Given an :class:`httplib.HTTPResponse` instance ``r``, return a
        corresponding :class:`urllib3.response.HTTPResponse` object.

        Remaining parameters are passed to the HTTPResponse constructor, along
        with ``original_response=r``.
        """

        headers = HTTPHeaderDict()
        for k, v in r.getheaders():
            headers.add(k, v)

        # HTTPResponse objects in Python 3 don't have a .strict attribute
        strict = getattr(r, 'strict', 0)
        r = ResponseCls(body=r,
                           headers=headers,
                           status=r.status,
                           version=r.version,
                           reason=r.reason,
                           strict=strict,
                           original_response=r,
                           **response_kw)

        yield from r.init()
        return r

    # Backwards-compatibility methods for httplib.HTTPResponse
    def getheaders(self):
        return self.headers

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    # Overrides from io.IOBase
    def close(self):
        if self.closed:
            return
        if type(self._fp) == asyncio.StreamReader:
            self._fp.feed_eof()
            self._fp._buffer = b'' # empty buffer
        else:
            self._fp.close()

    @property
    def closed(self):
        if self._fp is None:
            return True
        elif type(self._fp) == asyncio.StreamReader:
            return self._fp.at_eof()
        elif hasattr(self._fp, 'closed'):
            return self._fp.closed
        elif hasattr(self._fp, 'isclosed'):  # Python 2
            return self._fp.isclosed()
        else:
            return True

    def fileno(self):
        if self._fp is None:
            raise IOError("HTTPResponse has no file to get a fileno from")
        elif hasattr(self._fp, "fileno"):
            return self._fp.fileno()
        else:
            raise IOError("The file-like object this HTTPResponse is wrapped "
                          "around has no file descriptor")

    def flush(self):
        if self._fp is not None and hasattr(self._fp, 'flush'):
            return self._fp.flush()

    def readable(self):
        # This method is required for `io` module compatibility.
        return True

    @asyncio.coroutine
    def readinto(self, b):
        # This method is required for `io` module compatibility.
        bLen = len(b)
        bytes = yield from self._fp.read(bLen)
        bytesLen = len(bytes)
        b[:bytesLen] = bytes
        return len(bytes)
        # temp = yield from self.read(len(b))
        # if len(temp) == 0:
        #     return 0
        # else:
        #     b[:len(temp)] = temp
        #     return len(temp)
