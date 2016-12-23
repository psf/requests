# -*- coding: utf-8 -*-

"""
requests._internal_utils
~~~~~~~~~~~~~~

Provides utility functions that are consumed internally by Requests
which depend on extremely few external helpers (such as compat)
"""

from .compat import is_py2, builtin_str, str

import sys


def to_native_string(string, encoding='ascii'):
    """Given a string object, regardless of type, returns a representation of
    that string in the native string type, encoding and decoding where
    necessary. This assumes ASCII unless told otherwise.
    """
    if isinstance(string, builtin_str):
        out = string
    else:
        if is_py2:
            out = string.encode(encoding)
        else:
            out = string.decode(encoding)

    return out


def unicode_is_ascii(u_string):
    """Determine if unicode string only contains ASCII characters.

    :param str u_string: unicode string to check. Must be unicode
        and not Python 2 `str`.
    :rtype: bool
    """
    assert isinstance(u_string, str)
    try:
        u_string.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False


def delete_module(modname):
    """
    Delete module and sub-modules from `sys.module`
    """
    try:
        _ = sys.modules[modname]
    except KeyError:
        raise ValueError("Module not found in sys.modules: '{}'".format(modname))

    for module in list(sys.modules.keys()):
        if module and module.startswith(modname):
            del sys.modules[module]


def reload_module(module):
    try:
        # For Python 2.x
        reload(module)
    except (ImportError, NameError):
        # For <= Python3.3:
        import imp
        imp.reload(module)
    except (ImportError, NameError):
        # For >= Python3.4
        import importlib
        importlib.reload(module)
