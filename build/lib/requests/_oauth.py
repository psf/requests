# -*- coding: utf-8 -*-

"""
requests._oauth
~~~~~~~~~~~~~~~

This module comtains the path hack neccesary for oauthlib to be vendored into requests
while allowing upstream changes.
"""

import os
import sys

try:
    from oauthlib.oauth1 import rfc5849
    from oauthlib.common import extract_params
    from oauthlib.oauth1.rfc5849 import (Client, SIGNATURE_HMAC, SIGNATURE_TYPE_AUTH_HEADER)
except ImportError:
    path = os.path.abspath('/'.join(__file__.split('/')[:-1]+['packages']))
    sys.path.insert(0, path)
    from oauthlib.oauth1 import rfc5849
    from oauthlib.common import extract_params
    from oauthlib.oauth1.rfc5849 import (Client, SIGNATURE_HMAC, SIGNATURE_TYPE_AUTH_HEADER)