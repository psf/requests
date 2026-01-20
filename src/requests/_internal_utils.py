"""
requests._internal_utils
~~~~~~~~~~~~~~

Provides utility functions that are consumed internally by Requests
which depend on extremely few external helpers (such as compat)
"""
import re

from .compat import builtin_str

_VALID_HEADER_NAME_RE_BYTE = re.compile(rb"^[^:\s][^:\r\n]*$")
_VALID_HEADER_NAME_RE_STR = re.compile(r"^[^:\s][^:\r\n]*$")
_VALID_HEADER_VALUE_RE_BYTE = re.compile(rb"^\S[^\r\n]*$|^$")
_VALID_HEADER_VALUE_RE_STR = re.compile(r"^\S[^\r\n]*$|^$")

_HEADER_VALIDATORS_STR = (_VALID_HEADER_NAME_RE_STR, _VALID_HEADER_VALUE_RE_STR)
_HEADER_VALIDATORS_BYTE = (_VALID_HEADER_NAME_RE_BYTE, _VALID_HEADER_VALUE_RE_BYTE)
HEADER_VALIDATORS = {
    bytes: _HEADER_VALIDATORS_BYTE,
    str: _HEADER_VALIDATORS_STR,
}


def to_native_string(string, encoding="ascii"):
    """
    Converts a string-like object to the native string type used by the system, handling both byte strings and Unicode strings appropriately. This is necessary in Requests to ensure consistent string handling across different Python versions and input types, particularly when processing HTTP response bodies or headers that may arrive as bytes.
    
    Args:
        string: A string or bytes object to convert to a native string.
        encoding: The encoding to use when decoding bytes (default: 'ascii').
    
    Returns:
        The input converted to a native string (unicode in Python 2, str in Python 3), ensuring compatibility with the rest of the Requests library's string operations.
    """
    if isinstance(string, builtin_str):
        out = string
    else:
        out = string.decode(encoding)

    return out


def unicode_is_ascii(u_string):
    """
    Check if a Unicode string contains only ASCII characters, ensuring safe handling of text in HTTP requests.
    
    This function is used internally by Requests to validate that string data does not contain non-ASCII characters that could cause encoding issues when sending HTTP headers or URLs. It helps maintain compatibility and prevent errors during request construction.
    
    Args:
        u_string: The Unicode string to check for ASCII-only content
    
    Returns:
        True if the string contains only ASCII characters, False otherwise
    """
    assert isinstance(u_string, str)
    try:
        u_string.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False
