from __future__ import absolute_import
import sys

try:
    from . import urllib3
except ImportError:
    import urllib3
    sys.modules['%s.urllib3' % __name__] = urllib3

try:
    from . import chardet
except ImportError:
    import chardet
    sys.modules['%s.chardet' % __name__] = chardet
