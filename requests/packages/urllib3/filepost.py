# urllib3/filepost.py
# Copyright 2008-2011 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php

import codecs
import mimetools
import mimetypes

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO # pylint: disable-msg=W0404


writer = codecs.lookup('utf-8')[3]


def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'


def encode_multipart_formdata(fields, boundary=None):
    """
    Encode a dictionary of ``fields`` using the multipart/form-data mime format.

    :param fields:
        Dictionary of fields. The key is treated as the field name, and the
        value as the body of the form-data. If the value is a tuple of two
        elements, then the first element is treated as the filename of the
        form-data section.

    :param boundary:
        If not specified, then a random boundary will be generated using
        :func:`mimetools.choose_boundary`.
    """
    body = StringIO()
    if boundary is None:
        boundary = mimetools.choose_boundary()

    for fieldname, value in fields.iteritems():
        body.write('--%s\r\n' % (boundary))

        if isinstance(value, tuple):
            filename, data = value
            writer(body).write('Content-Disposition: form-data; name="%s"; '
                               'filename="%s"\r\n' % (fieldname, filename))
            body.write('Content-Type: %s\r\n\r\n' %
                       (get_content_type(filename)))
        else:
            data = value
            writer(body).write('Content-Disposition: form-data; name="%s"\r\n'
                               % (fieldname))
            body.write('Content-Type: text/plain\r\n\r\n')

        if isinstance(data, int):
            data = str(data)  # Backwards compatibility

        if isinstance(data, unicode):
            writer(body).write(data)
        else:
            body.write(data)

        body.write('\r\n')

    body.write('--%s--\r\n' % (boundary))

    content_type = 'multipart/form-data; boundary=%s' % boundary

    return body.getvalue(), content_type
