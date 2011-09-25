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
