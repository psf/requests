# -*- coding: utf-8 -*-

"""
requests._oauth
~~~~~~~~~~~~~~~

This module contains the path hack necessary for oauthlib to be vendored into
requests while allowing upstream changes.
"""

import os
import sys

try:
    from oauthlib.oauth1 import rfc5849
    from oauthlib.common import extract_params
    from oauthlib.oauth1.rfc5849 import (Client, SIGNATURE_HMAC, SIGNATURE_TYPE_AUTH_HEADER)
except ImportError:
    from .packages import oauthlib
    sys.modules['oauthlib'] = oauthlib
    from oauthlib.oauth1 import rfc5849
    from oauthlib.common import extract_params
    from oauthlib.oauth1.rfc5849 import (Client, SIGNATURE_HMAC, SIGNATURE_TYPE_AUTH_HEADER)
