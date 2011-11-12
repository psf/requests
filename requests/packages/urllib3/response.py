# urllib3/response.py
# Copyright 2008-2011 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php

import gzip
import logging
import zlib


try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO # pylint: disable-msg=W0404


from .exceptions import HTTPError


log = logging.getLogger(__name__)


def decode_gzip(data):
    gzipper = gzip.GzipFile(fileobj=StringIO(data))
    return gzipper.read()


def decode_deflate(data):
    try:
        return zlib.decompress(data)
    except zlib.error:
        return zlib.decompress(data, -zlib.MAX_WBITS)


class HTTPResponse(object):
    """
    HTTP Response container.

    Backwards-compatible to httplib's HTTPResponse but the response ``body`` is
    loaded and decoded on-demand when the ``data`` property is accessed.

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

    CONTENT_DECODERS = {
        'gzip': decode_gzip,
        'deflate': decode_deflate,
    }

    def __init__(self, body='', headers=None, status=0, version=0, reason=None,
                 strict=0, preload_content=True, decode_content=True,
                 original_response=None, pool=None, connection=None):
        self.headers = headers or {}
        self.status = status
        self.version = version
        self.reason = reason
        self.strict = strict

        self._decode_content = decode_content
        self._body = None
        self._fp = None
        self._original_response = original_response

        self._pool = pool
        self._connection = connection

        if hasattr(body, 'read'):
            self._fp = body

        if preload_content:
            self._body = self.read(decode_content=decode_content)

    def release_conn(self):
        if not self._pool or not self._connection:
            return

        self._pool._put_conn(self._connection)
        self._connection = None

    @property
    def data(self):
        # For backwords-compat with earlier urllib3 0.4 and earlier.
        if self._body:
            return self._body

        if self._fp:
            return self.read(decode_content=self._decode_content,
                             cache_content=True)

    def read(self, amt=None, decode_content=True, cache_content=False):
        """
        Similar to :meth:`httplib.HTTPResponse.read`, but with two additional
        parameters: ``decode_content`` and ``cache_content``.

        :param amt:
            How much of the content to read. If specified, decoding and caching
            is skipped because we can't decode partial content nor does it make
            sense to cache partial content as the full response.

        :param decode_content:
            If True, will attempt to decode the body based on the
            'content-encoding' header. (Overridden if ``amt`` is set.)

        :param cache_content:
            If True, will save the returned data such that the same result is
            returned despite of the state of the underlying file object. This
            is useful if you want the ``.data`` property to continue working
            after having ``.read()`` the file object. (Overridden if ``amt`` is
            set.)
        """
        content_encoding = self.headers.get('content-encoding')
        decoder = self.CONTENT_DECODERS.get(content_encoding)

        data = self._fp and self._fp.read(amt)

        try:

            if amt:
                return data

            if not decode_content or not decoder:
                if cache_content:
                    self._body = data

                return data

            try:
                data = decoder(data)
            except IOError:
                raise HTTPError("Received response with content-encoding: %s, but "
                                "failed to decode it." % content_encoding)

            if cache_content:
                self._body = data

            return data

        finally:

            if self._original_response and self._original_response.isclosed():
                self.release_conn()

    @staticmethod
    def from_httplib(r, **response_kw):
        """
        Given an :class:`httplib.HTTPResponse` instance ``r``, return a
        corresponding :class:`urllib3.response.HTTPResponse` object.

        Remaining parameters are passed to the HTTPResponse constructor, along
        with ``original_response=r``.
        """

        return HTTPResponse(body=r,
                            headers=dict(r.getheaders()),
                            status=r.status,
                            version=r.version,
                            reason=r.reason,
                            strict=r.strict,
                            original_response=r,
                            **response_kw)

    # Backwards-compatibility methods for httplib.HTTPResponse
    def getheaders(self):
        return self.headers

    def getheader(self, name, default=None):
        return self.headers.get(name, default)
