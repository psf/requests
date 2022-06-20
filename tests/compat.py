import warnings

try:
    import StringIO
except ImportError:
    import io as StringIO

try:
    from cStringIO import StringIO as cStringIO
except ImportError:
    cStringIO = None


def u(s):
    warnings.warn(
        (
            "This helper function is no longer relevant in Python 3. "
            "Usage of this alias should be discontinued as it will be "
            "removed in a future release of Requests."
        ),
        DeprecationWarning,
    )
    return s
