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

import warnings

import urllib3

from .exceptions import RequestsDependencyWarning

try:
    from charset_normalizer import __version__ as charset_normalizer_version
except ImportError:
    charset_normalizer_version = None  # type: ignore[assignment]

try:
    from chardet import __version__ as chardet_version
except ImportError:
    chardet_version = None  # type: ignore[assignment]


def check_compatibility(urllib3_ver: str, chardet_ver: "str | None", charset_normalizer_ver: "str | None") -> None:
    """Check compatibility of dependency versions."""
    urllib3_version = urllib3_ver.split(".")
    assert urllib3_version != ["dev"]  # Verify urllib3 isn't installed from git.

    # Sometimes, urllib3 only reports its version as 16.1.
    if len(urllib3_version) == 2:
        urllib3_version.append("0")

    # Check urllib3 for compatibility.
    urllib3_major, urllib3_minor = int(urllib3_version[0]), int(urllib3_version[1])  # noqa: F811
    # urllib3 >= 1.21.1
    assert urllib3_major >= 1
    if urllib3_major == 1:
        assert urllib3_minor >= 21

    # Check charset_normalizer for compatibility.
    if chardet_ver:
        chardet_version_tuple = tuple(int(x) for x in chardet_ver.split(".")[:3])
        # chardet_version >= 3.0.2, < 6.0.0
        assert (3, 0, 2) <= chardet_version_tuple < (6, 0, 0)
    elif charset_normalizer_ver:
        charset_version_tuple = tuple(int(x) for x in charset_normalizer_ver.split(".")[:3])
        # charset_normalizer >= 2.0.0 < 4.0.0
        assert (2, 0, 0) <= charset_version_tuple < (4, 0, 0)
    else:
        warnings.warn(
            "Unable to find acceptable character detection dependency "
            "(chardet or charset_normalizer).",
            RequestsDependencyWarning,
        )


def _check_cryptography(cryptography_ver: str) -> None:
    """Check cryptography version for compatibility."""
    # cryptography < 1.3.4
    try:
        crypto_ver_list = list(map(int, cryptography_ver.split(".")))
    except ValueError:
        return

    if crypto_ver_list < [1, 3, 4]:
        warning = f"Old version of cryptography ({crypto_ver_list}) may cause slowdown."
        warnings.warn(warning, RequestsDependencyWarning)


# Check imported dependencies for compatibility.
try:
    check_compatibility(
        urllib3.__version__,  # type: ignore[attr-defined]
        chardet_version, charset_normalizer_version
    )
except (AssertionError, ValueError):
    warnings.warn(
        f"urllib3 ({urllib3.__version__}) or chardet ({chardet_version})/"  # type: ignore[attr-defined]
        f"charset_normalizer ({charset_normalizer_version}) doesn't match a supported "
        f"version!",
        RequestsDependencyWarning,
    )

# Attempt to enable urllib3's fallback for SNI support
# if the standard library doesn't support SNI or the
# 'ssl' library isn't available.
try:
    try:
        import ssl
    except ImportError:
        ssl = None  # type: ignore[assignment]

    if not getattr(ssl, "HAS_SNI", False):
        from urllib3.contrib import pyopenssl

        pyopenssl.inject_into_urllib3()

        # Check cryptography version
        from cryptography import __version__ as cryptography_version

        _check_cryptography(cryptography_version)
except ImportError:
    pass

# urllib3's DependencyWarnings should be silenced.
# pylint: disable=wrong-import-position
from urllib3.exceptions import DependencyWarning

warnings.simplefilter("ignore", DependencyWarning)

# Set default logging handler to avoid "No handler found" warnings.
import logging
from logging import NullHandler

from . import packages, utils
from .__version__ import (
    __author__,
    __author_email__,
    __build__,
    __cake__,
    __copyright__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
)
from .api import delete, get, head, options, patch, post, put, request
# pylint: disable=redefined-builtin
from .exceptions import (
    ConnectionError,
    ConnectTimeout,
    FileModeWarning,
    HTTPError,
    JSONDecodeError,
    ReadTimeout,
    RequestException,
    Timeout,
    TooManyRedirects,
    URLRequired,
)
# pylint: enable=redefined-builtin
from .models import PreparedRequest, Request, Response
from .sessions import Session, session
from .status_codes import codes
# pylint: enable=wrong-import-position

logging.getLogger(__name__).addHandler(NullHandler())

# FileModeWarnings go off per the default.
warnings.simplefilter("default", FileModeWarning, append=True)
