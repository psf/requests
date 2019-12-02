# -*- coding: utf-8 -*-

#   __
#  /__)  _  _     _   _ _/   _
# / (   (- (/ (/ (- _)  /  _)
#          /

"""
Requests HTTP Library
~~~~~~~~~~~~~~~~~~~~~

Requests is an HTTP library, written in Python, for human beings.
Basic GET usage:

   >>> import requests
   >>> r = requests.get('https://www.python.org')
   >>> r.status_code
   200
   >>> b'Python is a programming language' in r.content
   True

... or POST:

   >>> payload = dict(key1='value1', key2='value2')
   >>> r = requests.post('https://httpbin.org/post', data=payload)
   >>> print(r.text)
   {
     ...
     "form": {
       "key1": "value1",
       "key2": "value2"
     },
     ...
   }

The other HTTP methods are supported - see `requests.api`. Full documentation
is at <https://requests.readthedocs.io>.

:copyright: (c) 2017 by Kenneth Reitz.
:license: Apache 2.0, see LICENSE for more details.
"""

import urllib3
import chardet
import warnings
from .exceptions import RequestsDependencyWarning


def _check_version_compatibility(package, min_version=None, max_version=None, exceptions=None,
                                 closed_interval=(True, True), version_components=3):
    """Check the version compatibility of external libraries.

    :param package: external library object.
    :param min_version: a tuple of minimum version requirements.
    :param max_version: a tuple of maximum version requirements.
    :param exceptions: a list of versions that we need to exclude.
    :param closed_interval: a tuple that allow you to decide open interval (False) and
        closed interval (True) of minimum version and maximum version.
    :param version_components: how many version components that we need to compare.
    """
    package_version = getattr(package, '__version__', None)
    if not package_version:
        return warnings.warn("{} doesn't has a version attribute!".format(package.__name__))
    base_version = list(map(int, package_version.split('.')[:version_components]))
    # fill out missing entries
    missing_entries = [0] * (version_components - len(base_version))
    version = tuple(base_version + missing_entries)

    try:
        if min_version:
            assert version >= min_version if closed_interval[0] else version > min_version
        if max_version:
            assert version <= max_version if closed_interval[1] else version < max_version
        if exceptions:
            assert version not in exceptions
    except (AssertionError, ValueError):
        warnings.warn("{} ({}) doesn't match a supported version!".format(
            package.__name__, package.__version__))


# Check imported dependencies for compatibility.
# urllib3 >= 1.21.1, <1.26, !=1.25.0, !=1.25.1
_check_version_compatibility(urllib3, min_version=(1, 21, 1), max_version=(1, 26, 0),
                             exceptions=[(1, 25, 0), (1, 25, 1)], closed_interval=(True, False))
# chardet >= 3.0.2, < 3.1.0
_check_version_compatibility(chardet, min_version=(3, 0, 2), max_version=(3, 1, 0),
                             closed_interval=(True, False))

# Attempt to enable urllib3's SNI support, if possible
try:
    from urllib3.contrib import pyopenssl
    pyopenssl.inject_into_urllib3()

    # Check cryptography version
    import cryptography
    # cryptography >= 1.3.4
    _check_version_compatibility(cryptography, min_version=(1, 3, 4))
except ImportError:
    pass

# urllib3's DependencyWarnings should be silenced.
from urllib3.exceptions import DependencyWarning
warnings.simplefilter('ignore', DependencyWarning)

from .__version__ import __title__, __description__, __url__, __version__
from .__version__ import __build__, __author__, __author_email__, __license__
from .__version__ import __copyright__, __cake__

from . import utils
from . import packages
from .models import Request, Response, PreparedRequest
from .api import request, get, head, post, patch, put, delete, options
from .sessions import session, Session
from .status_codes import codes
from .exceptions import (
    RequestException, Timeout, URLRequired,
    TooManyRedirects, HTTPError, ConnectionError,
    FileModeWarning, ConnectTimeout, ReadTimeout
)

# Set default logging handler to avoid "No handler found" warnings.
import logging
from logging import NullHandler

logging.getLogger(__name__).addHandler(NullHandler())

# FileModeWarnings go off per the default.
warnings.simplefilter('default', FileModeWarning, append=True)
