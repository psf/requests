# -*- coding: utf-8 -*-

"""Requests test package initialisation."""

import warnings

try:
    import urllib3 as urllib3_package
except ImportError:
    urllib3_package = False

from requests.packages import urllib3 as urllib3_bundle

if urllib3_package is urllib3_bundle:
    from urllib3.exceptions import SNIMissingWarning
else:
    from requests.packages.urllib3.exceptions import SNIMissingWarning

# urllib3 sets SNIMissingWarning to only go off once,
# while this test suite requires it to always fire
# so that it occurs during test_requests.test_https_warnings
warnings.simplefilter('always', SNIMissingWarning)
