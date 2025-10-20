"""
requests.compat
~~~~~~~~~~~~~~~

This module previously handled import compatibility issues
between Python 2 and Python 3. It remains for backwards
compatibility until the next major version.
"""

from __future__ import annotations

import importlib
import sys
from types import ModuleType
from typing import Optional, Tuple, Type

# -------
# urllib3
# -------
try:
    from urllib3 import __version__ as urllib3_version  # type: ignore[attr-defined]
except (ImportError, AttributeError):
    urllib3_version = "0.0.0"  # Fallback version

# Detect which major version of urllib3 is being used.
try:
    is_urllib3_1 = int(urllib3_version.split(".")[0]) == 1
except (TypeError, AttributeError):
    # If we can't discern a version, prefer old functionality.
    is_urllib3_1 = True

# -------------------
# Character Detection
# -------------------


def _resolve_char_detection() -> Optional[ModuleType]:
    """Find supported character detection libraries."""
    chardet_module: Optional[ModuleType] = None
    for lib in ("chardet", "charset_normalizer"):
        if chardet_module is None:
            try:
                chardet_module = importlib.import_module(lib)
            except ImportError:
                pass
    return chardet_module


chardet = _resolve_char_detection()

# -------
# Pythons
# -------

# Syntax sugar.
_ver = sys.version_info

#: Python 2.x?
is_py2 = _ver[0] == 2

#: Python 3.x?
is_py3 = _ver[0] == 3

# json/simplejson module import resolution
has_simplejson = False
try:
    import simplejson as json  # type: ignore[import-untyped]

    has_simplejson = True
except ImportError:
    import json

if has_simplejson:
    # pylint: disable=import-error
    from simplejson import JSONDecodeError  # type: ignore[import-untyped]
    # pylint: enable=import-error
else:
    from json import JSONDecodeError

# Keep OrderedDict for backwards compatibility.
# pylint: disable=wrong-import-position
from collections import OrderedDict
from collections.abc import Callable, Mapping, MutableMapping
from http import cookiejar as cookielib
from http.cookies import Morsel
from io import StringIO

# --------------
# Legacy Imports
# --------------
from urllib.parse import (
    quote,
    quote_plus,
    unquote,
    unquote_plus,
    urldefrag,
    urlencode,
    urljoin,
    urlparse,
    urlsplit,
    urlunparse,
)
from urllib.request import (
    getproxies,
    getproxies_environment,
    parse_http_list,
    proxy_bypass,
)

# Handle proxy_bypass_environment which doesn't exist in urllib.request
try:
    from urllib.request import proxy_bypass_environment  # type: ignore[attr-defined]
except (ImportError, AttributeError):
    # Fallback if not available
    def proxy_bypass_environment(host: str, proxies: Optional[dict[str, str]] = None) -> bool:  # type: ignore[misc]  # pylint: disable=unused-argument
        """Stub for proxy_bypass_environment when not available."""
        return False

# pylint: enable=wrong-import-position

# Compatibility aliases - intentionally redefine built-ins for backwards compatibility
# pylint: disable=redefined-builtin, invalid-name, self-assigning-variable
builtin_str = str
str = str  # type: ignore[assignment]  # Re-export for backwards compatibility
bytes = bytes  # type: ignore[assignment]  # Re-export for backwards compatibility
# pylint: enable=redefined-builtin, invalid-name, self-assigning-variable
basestring: Tuple[Type[str], Type[bytes]] = (str, bytes)
numeric_types: Tuple[Type[int], Type[float]] = (int, float)
integer_types: Tuple[Type[int]] = (int,)

# Explicit exports for mypy
__all__ = [
    "urllib3_version",
    "is_urllib3_1",
    "chardet",
    "is_py2",
    "is_py3",
    "has_simplejson",
    "json",
    "JSONDecodeError",
    "OrderedDict",
    "Callable",
    "Mapping",
    "MutableMapping",
    "cookielib",
    "Morsel",
    "StringIO",
    "quote",
    "quote_plus",
    "unquote",
    "unquote_plus",
    "urldefrag",
    "urlencode",
    "urljoin",
    "urlparse",
    "urlsplit",
    "urlunparse",
    "getproxies",
    "getproxies_environment",
    "parse_http_list",
    "proxy_bypass",
    "proxy_bypass_environment",
    "builtin_str",
    "str",
    "bytes",
    "basestring",
    "numeric_types",
    "integer_types",
]
