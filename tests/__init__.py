"""Requests test package initialisation."""

import warnings

from urllib3.exceptions import SNIMissingWarning

# urllib3 sets SNIMissingWarning to only go off once,
# while this test suite requires it to always fire
# so that it occurs during test_requests.test_https_warnings
warnings.simplefilter("always", SNIMissingWarning)
