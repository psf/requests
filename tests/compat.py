# -*- coding: utf-8 -*-

try:
    import StringIO
except ImportError:
    import io as StringIO

try:
    from cStringIO import StringIO as cStringIO
except ImportError:
    cStringIO = None


def u(s):
    return s
