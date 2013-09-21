#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
certs.py
~~~~~~~~

This module returns the preferred default CA certificate bundle.

If you are packaging Requests, e.g., for a Linux distribution or a managed
environment, you can change the definition of where() to return a separately
packaged CA bundle.
"""

from pkg_resources import resource_string


def where():
    """Return the preferred certificate bundle."""
    # vendored bundle inside Requests
    return resource_string(__name__, "cacert.pem")

if __name__ == '__main__':
    print(where())
