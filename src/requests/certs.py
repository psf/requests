#!/usr/bin/env python

"""
requests.certs
~~~~~~~~~~~~~~

This module returns the preferred default CA certificate bundle. There is
only one — the one from the certifi package.

If you are packaging Requests, e.g., for a Linux distribution or a managed
environment, you can change the definition of where() to return a separately
packaged CA bundle.
"""

from certifi import where as certifi_where


def where() -> str:
    """Return the path to Requests' default CA bundle.

    This is the CA bundle path from ``certifi``. The bundle used by an
    individual request may be different because ``verify`` can be overridden
    per-request, on a ``Session``, or via ``REQUESTS_CA_BUNDLE`` /
    ``CURL_CA_BUNDLE``.
    """
    return certifi_where()


if __name__ == "__main__":
    print(where())
