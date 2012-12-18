#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
certs.py
~~~~~~~~

This module returns the preferred default CA certificate bundle.

Preference order:
    1. The certifi Python package, if available
    2. The operating system's bundle, if available
    3. The vendored bundle inside Requests
"""

import os.path

certifi = None
try:
    import certifi
except ImportError:
    pass

# common paths for the OS's CA certificate bundle
POSSIBLE_CA_BUNDLE_PATHS = [
        # Red Hat, CentOS, Fedora and friends (provided by the ca-certificates package):
        '/etc/pki/tls/certs/ca-bundle.crt',
        # Ubuntu, Debian, and friends (provided by the ca-certificates package):
        '/etc/ssl/certs/ca-certificates.crt',
        # FreeBSD (provided by the ca_root_nss package):
        '/usr/local/share/certs/ca-root-nss.crt',
        # openSUSE (provided by the ca-certificates package), the 'certs' directory is the
        # preferred way but may not be supported by the SSL module, thus it has 'ca-bundle.pem'
        # as a fallback (which is generated from pem files in the 'certs' directory):
        '/etc/ssl/ca-bundle.pem',
]

def get_os_ca_bundle_path():
    """Try to pick an available CA certificate bundle provided by the OS."""
    for path in POSSIBLE_CA_BUNDLE_PATHS:
        if os.path.exists(path):
            return path
    return None

def where():
    """Return the preferred certificate bundle."""
    if certifi:
        return certifi.where()

    os_bundle_path = get_os_ca_bundle_path()
    if os_bundle_path:
        return os_bundle_path

    return os.path.join(os.path.dirname(__file__), 'cacert.pem')

if __name__ == '__main__':
    print(where())
