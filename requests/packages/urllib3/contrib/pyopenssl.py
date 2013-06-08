'''SSL with SNI-support for Python 2.

This needs the following packages installed:

* pyOpenSSL (tested with 0.13)
* ndg-httpsclient (tested with 0.3.2)
* pyasn1 (tested with 0.1.6)

To activate it call :func:`~urllib3.contrib.pyopenssl.inject_into_urllib3`.
This can be done in a ``sitecustomize`` module, or at any other time before
your application begins using ``urllib3``, like this::

    try:
        import urllib3.contrib.pyopenssl
        urllib3.contrib.pyopenssl.inject_into_urllib3()
    except ImportError:
        pass

Now you can use :mod:`urllib3` as you normally would, and it will support SNI
when the required modules are installed.
'''

from ndg.httpsclient.ssl_peer_verification import (ServerSSLCertVerification,
                                                   SUBJ_ALT_NAME_SUPPORT)
from ndg.httpsclient.subj_alt_name import SubjectAltName
import OpenSSL.SSL
from pyasn1.codec.der import decoder as der_decoder
from socket import _fileobject
import ssl

from .. import connectionpool
from .. import util

__all__ = ['inject_into_urllib3', 'extract_from_urllib3']

# SNI only *really* works if we can read the subjectAltName of certificates.
HAS_SNI = SUBJ_ALT_NAME_SUPPORT

# Map from urllib3 to PyOpenSSL compatible parameter-values.
_openssl_versions = {
    ssl.PROTOCOL_SSLv23: OpenSSL.SSL.SSLv23_METHOD,
    ssl.PROTOCOL_SSLv3: OpenSSL.SSL.SSLv3_METHOD,
    ssl.PROTOCOL_TLSv1: OpenSSL.SSL.TLSv1_METHOD,
}
_openssl_verify = {
    ssl.CERT_NONE: OpenSSL.SSL.VERIFY_NONE,
    ssl.CERT_OPTIONAL: OpenSSL.SSL.VERIFY_PEER,
    ssl.CERT_REQUIRED: OpenSSL.SSL.VERIFY_PEER
                       + OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
}


orig_util_HAS_SNI = util.HAS_SNI
orig_connectionpool_ssl_wrap_socket = connectionpool.ssl_wrap_socket


def inject_into_urllib3():
    'Monkey-patch urllib3 with PyOpenSSL-backed SSL-support.'

    connectionpool.ssl_wrap_socket = ssl_wrap_socket
    util.HAS_SNI = HAS_SNI


def extract_from_urllib3():
    'Undo monkey-patching by :func:`inject_into_urllib3`.'

    connectionpool.ssl_wrap_socket = orig_connectionpool_ssl_wrap_socket
    util.HAS_SNI = orig_util_HAS_SNI


### Note: This is a slightly bug-fixed version of same from ndg-httpsclient.
def get_subj_alt_name(peer_cert):
    # Search through extensions
    dns_name = []
    if not SUBJ_ALT_NAME_SUPPORT:
        return dns_name

    general_names = SubjectAltName()
    for i in range(peer_cert.get_extension_count()):
        ext = peer_cert.get_extension(i)
        ext_name = ext.get_short_name()
        if ext_name != 'subjectAltName':
            continue

        # PyOpenSSL returns extension data in ASN.1 encoded form
        ext_dat = ext.get_data()
        decoded_dat = der_decoder.decode(ext_dat,
                                         asn1Spec=general_names)

        for name in decoded_dat:
            if not isinstance(name, SubjectAltName):
                continue
            for entry in range(len(name)):
                component = name.getComponentByPosition(entry)
                if component.getName() != 'dNSName':
                    continue
                dns_name.append(str(component.getComponent()))

    return dns_name


class WrappedSocket(object):
    '''API-compatibility wrapper for Python OpenSSL's Connection-class.'''

    def __init__(self, connection, socket):
        self.connection = connection
        self.socket = socket

    def makefile(self, mode, bufsize=-1):
        return _fileobject(self.connection, mode, bufsize)

    def settimeout(self, timeout):
        return self.socket.settimeout(timeout)

    def sendall(self, data):
        return self.connection.sendall(data)

    def close(self):
        return self.connection.shutdown()

    def getpeercert(self, binary_form=False):
        x509 = self.connection.get_peer_certificate()
        if not x509:
            raise ssl.SSLError('')

        if binary_form:
            return OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_ASN1,
                x509)

        return {
            'subject': (
                (('commonName', x509.get_subject().CN),),
            ),
            'subjectAltName': [
                ('DNS', value)
                for value in get_subj_alt_name(x509)
            ]
        }


def _verify_callback(cnx, x509, err_no, err_depth, return_code):
    return err_no == 0


def ssl_wrap_socket(sock, keyfile=None, certfile=None, cert_reqs=None,
                    ca_certs=None, server_hostname=None,
                    ssl_version=None):
    ctx = OpenSSL.SSL.Context(_openssl_versions[ssl_version])
    if certfile:
        ctx.use_certificate_file(certfile)
    if keyfile:
        ctx.use_privatekey_file(keyfile)
    if cert_reqs != ssl.CERT_NONE:
        ctx.set_verify(_openssl_verify[cert_reqs], _verify_callback)
    if ca_certs:
        try:
            ctx.load_verify_locations(ca_certs, None)
        except OpenSSL.SSL.Error as e:
            raise ssl.SSLError('bad ca_certs: %r' % ca_certs, e)

    cnx = OpenSSL.SSL.Connection(ctx, sock)
    cnx.set_tlsext_host_name(server_hostname)
    cnx.set_connect_state()
    try:
        cnx.do_handshake()
    except OpenSSL.SSL.Error as e:
        raise ssl.SSLError('bad handshake', e)

    return WrappedSocket(cnx, sock)
