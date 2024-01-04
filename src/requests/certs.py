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
from certifi import where as _where


def where() -> str:
    """Returns the path of the default CA-certs bundle that is included with
    the requests package. This function is essentially an alias of
    `certify.where`.

    Note that the default path is not necessarily the one being used, as it can
    be overridden through ``requests.Session().verify``,
    ``requests.Session().merge_environment_settings``,
    ``requests.get(verify=...)``, and others.

    """
    return _where()


if __name__ == "__main__":
    print(_where())
