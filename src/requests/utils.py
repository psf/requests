"""
requests.utils
~~~~~~~~~~~~~~

This module provides utility functions that are used within Requests
that are also useful for external consumption.
"""

import codecs
import contextlib
import io
import os
import re
import socket
import struct
import sys
import tempfile
import warnings
import zipfile
from collections import OrderedDict

from urllib3.util import make_headers, parse_url

from . import certs
from .__version__ import __version__

# to_native_string is unused here, but imported here for backwards compatibility
from ._internal_utils import (  # noqa: F401
    _HEADER_VALIDATORS_BYTE,
    _HEADER_VALIDATORS_STR,
    HEADER_VALIDATORS,
    to_native_string,
)
from .compat import (
    Mapping,
    basestring,
    bytes,
    getproxies,
    getproxies_environment,
    integer_types,
    is_urllib3_1,
)
from .compat import parse_http_list as _parse_list_header
from .compat import (
    proxy_bypass,
    proxy_bypass_environment,
    quote,
    str,
    unquote,
    urlparse,
    urlunparse,
)
from .cookies import cookiejar_from_dict
from .exceptions import (
    FileModeWarning,
    InvalidHeader,
    InvalidURL,
    UnrewindableBodyError,
)
from .structures import CaseInsensitiveDict

NETRC_FILES = (".netrc", "_netrc")

DEFAULT_CA_BUNDLE_PATH = certs.where()

DEFAULT_PORTS = {"http": 80, "https": 443}

# Ensure that ', ' is used to preserve previous delimiter behavior.
DEFAULT_ACCEPT_ENCODING = ", ".join(
    re.split(r",\s*", make_headers(accept_encoding=True)["accept-encoding"])
)


if sys.platform == "win32":
    # provide a proxy_bypass version on Windows without DNS lookups

    def proxy_bypass_registry(host):
        try:
            import winreg
        except ImportError:
            return False

        try:
            internetSettings = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            )
            # ProxyEnable could be REG_SZ or REG_DWORD, normalizing it
            proxyEnable = int(winreg.QueryValueEx(internetSettings, "ProxyEnable")[0])
            # ProxyOverride is almost always a string
            proxyOverride = winreg.QueryValueEx(internetSettings, "ProxyOverride")[0]
        except (OSError, ValueError):
            return False
        if not proxyEnable or not proxyOverride:
            return False

        # make a check value list from the registry entry: replace the
        # '<local>' string by the localhost entry and the corresponding
        # canonical entry.
        proxyOverride = proxyOverride.split(";")
        # filter out empty strings to avoid re.match return true in the following code.
        proxyOverride = filter(None, proxyOverride)
        # now check if we match one of the registry values.
        for test in proxyOverride:
            if test == "<local>":
                if "." not in host:
                    return True
            test = test.replace(".", r"\.")  # mask dots
            test = test.replace("*", r".*")  # change glob sequence
            test = test.replace("?", r".")  # change glob char
            if re.match(test, host, re.I):
                return True
        return False

    def proxy_bypass(host):  # noqa
        """Return True, if the host should be bypassed.

        Checks proxy settings gathered from the environment, if specified,
        or the registry.
        """
        if getproxies_environment():
            return proxy_bypass_environment(host)
        else:
            return proxy_bypass_registry(host)


def dict_to_sequence(d):
    """
    Converts a dictionary to an iterable of key-value pairs for internal sequence processing.
    
    This function ensures consistent handling of dictionary-like inputs by normalizing them into an iterable of (key, value) pairs, which is required for internal sequence operations within the Requests library. It supports both dictionary objects and other mappings by leveraging the `items()` method, enabling seamless integration with request data structures such as headers, parameters, and form data.
    
    Args:
        d: A dictionary or mapping object to be converted into an iterable of key-value pairs.
    
    Returns:
        An iterable of (key, value) tuples suitable for internal sequence processing.
    """

    if hasattr(d, "items"):
        d = d.items()

    return d


def super_len(o):
    """
    Calculate the remaining length of a file-like object or string from the current position, crucial for accurate content-length determination in HTTP requests.
    
    Args:
        o: A file-like object, string, or other object with length information. For file-like objects, the length is determined by __len__, .len, file size via fileno, or by seeking to the end if no length is available. If o is a string, it is encoded to UTF-8 if using urllib3 2.x+.
    
    Returns:
        The number of bytes remaining from the current position to the end of the object, or 0 if the length cannot be determined. The result is clamped to non-negative values.
    """
    total_length = None
    current_position = 0

    if not is_urllib3_1 and isinstance(o, str):
        # urllib3 2.x+ treats all strings as utf-8 instead
        # of latin-1 (iso-8859-1) like http.client.
        o = o.encode("utf-8")

    if hasattr(o, "__len__"):
        total_length = len(o)

    elif hasattr(o, "len"):
        total_length = o.len

    elif hasattr(o, "fileno"):
        try:
            fileno = o.fileno()
        except (io.UnsupportedOperation, AttributeError):
            # AttributeError is a surprising exception, seeing as how we've just checked
            # that `hasattr(o, 'fileno')`.  It happens for objects obtained via
            # `Tarfile.extractfile()`, per issue 5229.
            pass
        else:
            total_length = os.fstat(fileno).st_size

            # Having used fstat to determine the file length, we need to
            # confirm that this file was opened up in binary mode.
            if "b" not in o.mode:
                warnings.warn(
                    (
                        "Requests has determined the content-length for this "
                        "request using the binary size of the file: however, the "
                        "file has been opened in text mode (i.e. without the 'b' "
                        "flag in the mode). This may lead to an incorrect "
                        "content-length. In Requests 3.0, support will be removed "
                        "for files in text mode."
                    ),
                    FileModeWarning,
                )

    if hasattr(o, "tell"):
        try:
            current_position = o.tell()
        except OSError:
            # This can happen in some weird situations, such as when the file
            # is actually a special file descriptor like stdin. In this
            # instance, we don't know what the length is, so set it to zero and
            # let requests chunk it instead.
            if total_length is not None:
                current_position = total_length
        else:
            if hasattr(o, "seek") and total_length is None:
                # StringIO and BytesIO have seek but no usable fileno
                try:
                    # seek to end of file
                    o.seek(0, 2)
                    total_length = o.tell()

                    # seek back to current position to support
                    # partially read file-like objects
                    o.seek(current_position or 0)
                except OSError:
                    total_length = 0

    if total_length is None:
        total_length = 0

    return max(0, total_length - current_position)


def get_netrc_auth(url, raise_errors=False):
    """
    Returns the Requests-compatible authentication tuple (username, password) for a given URL using credentials stored in the netrc file.
    
    This function enables automatic authentication with HTTP servers by reading login credentials from the system's netrc file, which is commonly used to store credentials for various network services. It supports both explicit netrc file paths via the NETRC environment variable and default locations like ~/.netrc. The returned tuple can be directly used with Requests' auth parameter, simplifying secure access to authenticated APIs and services without hardcoding credentials.
    
    Args:
        url: The URL to determine authentication for, used to look up the appropriate host entry in the netrc file.
        raise_errors: If True, raises exceptions for netrc parsing or file access errors; otherwise, silently skips netrc authentication.
    
    Returns:
        A tuple of (username, password) if credentials are found in netrc for the URL's host, or None if no credentials are available or an error occurs and raise_errors is False.
    """

    netrc_file = os.environ.get("NETRC")
    if netrc_file is not None:
        netrc_locations = (netrc_file,)
    else:
        netrc_locations = (f"~/{f}" for f in NETRC_FILES)

    try:
        from netrc import NetrcParseError, netrc

        netrc_path = None

        for f in netrc_locations:
            loc = os.path.expanduser(f)
            if os.path.exists(loc):
                netrc_path = loc
                break

        # Abort early if there isn't one.
        if netrc_path is None:
            return

        ri = urlparse(url)
        host = ri.hostname

        try:
            _netrc = netrc(netrc_path).authenticators(host)
            if _netrc:
                # Return with login / password
                login_i = 0 if _netrc[0] else 1
                return (_netrc[login_i], _netrc[2])
        except (NetrcParseError, OSError):
            # If there was a parsing error or a permissions issue reading the file,
            # we'll just skip netrc auth unless explicitly asked to raise errors.
            if raise_errors:
                raise

    # App Engine hackiness.
    except (ImportError, AttributeError):
        pass


def guess_filename(obj):
    """
    Tries to guess the filename from an object's name attribute, primarily used to infer a default filename for file-like objects in HTTP responses.
    
    This helps Requests determine appropriate filenames when saving downloaded content, such as from a response's `Content-Disposition` header or when a file-like object is provided. It ensures consistent and meaningful default filenames in scenarios where no explicit name is provided.
    
    Args:
        obj: An object that may have a 'name' attribute, such as a file-like object or stream
    
    Returns:
        The base filename if the object's name is a valid string not starting or ending with angle brackets, otherwise None
    """
    name = getattr(obj, "name", None)
    if name and isinstance(name, basestring) and name[0] != "<" and name[-1] != ">":
        return os.path.basename(name)


def extract_zipped_paths(path):
    """
    Replace paths pointing to members within ZIP archives with the local extracted file path, enabling seamless access to archive contents without requiring manual extraction.
    
    This is particularly useful in the context of Requests, where users may need to work with compressed assets (e.g., bundled resources or downloadable archives) as if they were regular files. By automatically extracting archive members on-demand, the function supports efficient, transparent access to embedded content during HTTP workflows.
    
    Args:
        path: A file path that may refer to a member within a ZIP archive
    
    Returns:
        The local path to the extracted file if the archive and member are valid; otherwise, returns the original path unchanged
    """
    if os.path.exists(path):
        # this is already a valid path, no need to do anything further
        return path

    # find the first valid part of the provided path and treat that as a zip archive
    # assume the rest of the path is the name of a member in the archive
    archive, member = os.path.split(path)
    while archive and not os.path.exists(archive):
        archive, prefix = os.path.split(archive)
        if not prefix:
            # If we don't check for an empty prefix after the split (in other words, archive remains unchanged after the split),
            # we _can_ end up in an infinite loop on a rare corner case affecting a small number of users
            break
        member = "/".join([prefix, member])

    if not zipfile.is_zipfile(archive):
        return path

    zip_file = zipfile.ZipFile(archive)
    if member not in zip_file.namelist():
        return path

    # we have a valid zip archive and a valid member of that archive
    tmp = tempfile.gettempdir()
    extracted_path = os.path.join(tmp, member.split("/")[-1])
    if not os.path.exists(extracted_path):
        # use read + write to avoid the creating nested folders, we only want the file, avoids mkdir racing condition
        with atomic_open(extracted_path) as file_handler:
            file_handler.write(zip_file.read(member))
    return extracted_path


@contextlib.contextmanager
def atomic_open(filename):
    """
    Write a file to disk atomically, ensuring data integrity during writes.
    
    This function is used internally by Requests to safely write temporary data (such as response content) to disk without risking corruption or partial writes. By creating a temporary file first and then replacing the target file in a single atomic operation, it prevents race conditions and ensures that either the entire file is written successfully or no changes are made at all—critical for maintaining consistency when handling HTTP responses or cached data.
    
    Args:
        filename: The path to the file to be written; the final file will be created or replaced atomically
    """
    tmp_descriptor, tmp_name = tempfile.mkstemp(dir=os.path.dirname(filename))
    try:
        with os.fdopen(tmp_descriptor, "wb") as tmp_handler:
            yield tmp_handler
        os.replace(tmp_name, filename)
    except BaseException:
        os.remove(tmp_name)
        raise


def from_key_val_list(value):
    """
    Convert a value into an ordered dictionary representation, preserving key-value order for consistent serialization and HTTP header or form data processing.
    
    Args:
        value: An iterable of 2-tuples, a dictionary, or a similar structure containing key-value pairs. The function is used internally to normalize input data for HTTP requests, ensuring that order is preserved when sending data in requests (e.g., form data, headers, or query parameters), which is critical for predictable and correct HTTP behavior.
    """
    if value is None:
        return None

    if isinstance(value, (str, bytes, bool, int)):
        raise ValueError("cannot encode objects that are not 2-tuples")

    return OrderedDict(value)


def to_key_val_list(value):
    """
    Convert various input types into a list of key-value tuples, supporting flexible data formats for HTTP request parameters.
    
    Args:
        value: An object that may be a list of tuples, a dictionary, or another iterable. The function is used to normalize input data into a consistent format suitable for constructing HTTP request parameters, such as query strings or form data, ensuring compatibility across different data sources in the Requests library.
    """
    if value is None:
        return None

    if isinstance(value, (str, bytes, bool, int)):
        raise ValueError("cannot encode objects that are not 2-tuples")

    if isinstance(value, Mapping):
        value = value.items()

    return list(value)


# From mitsuhiko/werkzeug (used with permission).
def parse_list_header(value):
    """
    Parse comma-separated header values with support for quoted strings, as defined in RFC 2068 Section 2. This function is essential in Requests for correctly handling HTTP headers that contain list-like data, such as `Accept`, `Content-Type`, or `Set-Cookie`, where values may include commas within quoted strings or have case-sensitive content.
    
    Args:
        value: A string containing a list of header values, potentially including quoted substrings with embedded commas.
    
    Returns:
        A list of parsed values with quotes stripped and proper unquoting applied, preserving case sensitivity and allowing duplicate entries—ideal for reconstructing headers using `dump_header` while maintaining compliance with HTTP standards.
    """
    result = []
    for item in _parse_list_header(value):
        if item[:1] == item[-1:] == '"':
            item = unquote_header_value(item[1:-1])
        result.append(item)
    return result


# From mitsuhiko/werkzeug (used with permission).
def parse_dict_header(value):
    """
    Parse a header value containing key-value pairs (as defined in RFC 2068 Section 2) into a Python dictionary, enabling easy handling of structured header data in HTTP requests.
    
    This function is essential in Requests for processing HTTP headers that contain multiple named parameters, such as those used in Content-Type or Set-Cookie headers, allowing the library to correctly interpret and manipulate complex header values.
    
    Args:
        value: A string containing comma-separated key-value pairs, where values may be quoted.
    
    Returns:
        A dictionary mapping header keys to their corresponding values, with unquoted values and None for keys without values.
    """
    result = {}
    for item in _parse_list_header(value):
        if "=" not in item:
            result[item] = None
            continue
        name, value = item.split("=", 1)
        if value[:1] == value[-1:] == '"':
            value = unquote_header_value(value[1:-1])
        result[name] = value
    return result


# From mitsuhiko/werkzeug (used with permission).
def unquote_header_value(value, is_filename=False):
    """
    Unquotes header values to handle browser-specific quoting behavior, ensuring compatibility with real-world HTTP headers, particularly for filenames in file uploads.
    
    Args:
        value: The header value to unquote, typically from Content-Disposition or similar headers.
        is_filename: If True, treats the value as a filename and skips unquoting UNC paths (e.g., \\\\server\\share) to prevent breaking IE compatibility.
    
    Returns:
        The unquoted header value with backslashes and quotes properly normalized, preserving correct path formatting for filenames.
    """
    r"""Unquotes a header value.  (Reversal of :func:`quote_header_value`).
    This does not use the real unquoting but what browsers are actually
    using for quoting.

    :param value: the header value to unquote.
    :rtype: str
    """
    if value and value[0] == value[-1] == '"':
        # this is not the real unquoting, but fixing this so that the
        # RFC is met will result in bugs with internet explorer and
        # probably some other browsers as well.  IE for example is
        # uploading files with "C:\foo\bar.txt" as filename
        value = value[1:-1]

        # if this is a filename and the starting characters look like
        # a UNC path, then just return the value without quotes.  Using the
        # replace sequence below on a UNC path has the effect of turning
        # the leading double slash into a single slash and then
        # _fix_ie_filename() doesn't work correctly.  See #458.
        if not is_filename or value[:2] != "\\\\":
            return value.replace("\\\\", "\\").replace('\\"', '"')
    return value


def dict_from_cookiejar(cj):
    """
    Converts a CookieJar object into a dictionary of cookie names and values for easy access and manipulation.
    
    This function is particularly useful in the context of HTTP sessions where cookies need to be extracted, inspected, or passed to other components—such as when persisting session state or debugging request behavior. It enables seamless integration with other parts of the Requests library that expect simple key-value mappings.
    
    Args:
        cj: CookieJar object containing cookies to extract
    
    Returns:
        A dictionary mapping cookie names to their corresponding values
    """

    cookie_dict = {cookie.name: cookie.value for cookie in cj}
    return cookie_dict


def add_dict_to_cookiejar(cj, cookie_dict):
    """
    Converts a dictionary of cookies into a CookieJar for use in HTTP sessions.
    
    This function enables seamless integration of key-value cookie data into a CookieJar, which is essential for maintaining persistent session state across multiple requests. By leveraging Requests' session management capabilities, this allows developers to easily set cookies programmatically, supporting use cases like web scraping, API authentication, and stateful interactions with web services.
    
    Args:
        cj: CookieJar to insert cookies into.
        cookie_dict: Dictionary of cookie names and values to be added to the CookieJar.
    
    Returns:
        The updated CookieJar with the provided cookies inserted.
    """

    return cookiejar_from_dict(cookie_dict, cj)


def get_encodings_from_content(content):
    """
    Extracts character encodings declared in HTML or XML content to determine how the content should be decoded.
    
    This function is used internally by Requests to identify the encoding of response content when it's not explicitly provided in the HTTP headers. By parsing common encoding declarations in the document's metadata (such as `<meta charset="...">`, `<meta content="...;charset=...">`, or `<?xml encoding="...">`), Requests can correctly decode the response body, ensuring accurate text representation. This is especially important for handling non-ASCII content from web servers that don't specify encoding in headers.
    
    Args:
        content: Bytestring containing HTML or XML content to extract encoding declarations from.
    
    Returns:
        List of encoding strings found in the content, in order of discovery from different sources.
    """
    warnings.warn(
        (
            "In requests 3.0, get_encodings_from_content will be removed. For "
            "more information, please see the discussion on issue #2266. (This"
            " warning should only appear once.)"
        ),
        DeprecationWarning,
    )

    charset_re = re.compile(r'<meta.*?charset=["\']*(.+?)["\'>]', flags=re.I)
    pragma_re = re.compile(r'<meta.*?content=["\']*;?charset=(.+?)["\'>]', flags=re.I)
    xml_re = re.compile(r'^<\?xml.*?encoding=["\']*(.+?)["\'>]')

    return (
        charset_re.findall(content)
        + pragma_re.findall(content)
        + xml_re.findall(content)
    )


def _parse_content_type_header(header):
    """
    Parses a Content-Type header to extract the content type and its parameters, which is essential for correctly interpreting the format and encoding of HTTP response bodies.
    
    Args:
        header: The raw Content-Type header string from an HTTP response.
    
    Returns:
        A tuple containing the content type (e.g., 'application/json') and a dictionary of parameters (e.g., {'charset': 'utf-8'}), enabling proper handling of data encoding and parsing in Requests' internal processing.
    """

    tokens = header.split(";")
    content_type, params = tokens[0].strip(), tokens[1:]
    params_dict = {}
    items_to_strip = "\"' "

    for param in params:
        param = param.strip()
        if param:
            key, value = param, True
            index_of_equals = param.find("=")
            if index_of_equals != -1:
                key = param[:index_of_equals].strip(items_to_strip)
                value = param[index_of_equals + 1 :].strip(items_to_strip)
            params_dict[key.lower()] = value
    return content_type, params_dict


def get_encoding_from_headers(headers):
    """
    Extracts character encoding from HTTP headers to ensure proper text decoding.
    
    The function determines the appropriate encoding for response content based on the Content-Type header, which is essential for correctly interpreting text data in HTTP responses. This supports Requests' goal of simplifying HTTP interactions by automatically handling encoding detection, ensuring accurate decoding of response bodies without requiring manual intervention.
    
    Args:
        headers: Dictionary containing HTTP headers, typically from a response.
    """

    content_type = headers.get("content-type")

    if not content_type:
        return None

    content_type, params = _parse_content_type_header(content_type)

    if "charset" in params:
        return params["charset"].strip("'\"")

    if "text" in content_type:
        return "ISO-8859-1"

    if "application/json" in content_type:
        # Assume UTF-8 based on RFC 4627: https://www.ietf.org/rfc/rfc4627.txt since the charset was unset
        return "utf-8"


def stream_decode_response_unicode(iterator, r):
    """
    Stream-decodes response content from an iterator using the response's encoding, ensuring proper Unicode handling for large or chunked responses.
    
    Args:
        iterator: An iterable yielding byte chunks from the HTTP response body.
        r: The response object containing the encoding information to use for decoding.
    
    Returns:
        An iterator yielding decoded Unicode strings, with any invalid bytes replaced using the 'replace' error handler.
    """

    if r.encoding is None:
        yield from iterator
        return

    decoder = codecs.getincrementaldecoder(r.encoding)(errors="replace")
    for chunk in iterator:
        rv = decoder.decode(chunk)
        if rv:
            yield rv
    rv = decoder.decode(b"", final=True)
    if rv:
        yield rv


def iter_slices(string, slice_length):
    """
    Iterate over fixed-length slices of a string, useful for processing large text data in chunks during HTTP request handling.
    
    Args:
        string: The input string to be sliced.
        slice_length: The length of each slice; if None or non-positive, the entire string is returned as a single slice.
    """
    pos = 0
    if slice_length is None or slice_length <= 0:
        slice_length = len(string)
    while pos < len(string):
        yield string[pos : pos + slice_length]
        pos += slice_length


def get_unicode_from_response(r):
    """
    Extracts Unicode text from an HTTP response, handling encoding gracefully to ensure consistent text output.
    
    Args:
        r: Response object from which to extract Unicode content. The function attempts to use the charset specified in the response headers, falling back to error replacement if decoding fails.
    
    Returns:
        The response content as a Unicode string, with invalid characters replaced when necessary. This ensures reliable text processing across different encodings, which is essential for consistent data handling in web interactions.
    """
    warnings.warn(
        (
            "In requests 3.0, get_unicode_from_response will be removed. For "
            "more information, please see the discussion on issue #2266. (This"
            " warning should only appear once.)"
        ),
        DeprecationWarning,
    )

    tried_encodings = []

    # Try charset from content-type
    encoding = get_encoding_from_headers(r.headers)

    if encoding:
        try:
            return str(r.content, encoding)
        except UnicodeError:
            tried_encodings.append(encoding)

    # Fall back:
    try:
        return str(r.content, encoding, errors="replace")
    except TypeError:
        return r.content


# The unreserved URI characters (RFC 3986)
UNRESERVED_SET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" + "0123456789-._~"
)


def unquote_unreserved(uri):
    """
    Un-escape percent-encoded characters in a URI only if they represent unreserved characters, preserving reserved, illegal, and non-ASCII sequences unchanged.
    
    This ensures that URI components remain properly encoded according to RFC 3986, which is essential for maintaining valid and predictable URL structure when constructing or manipulating HTTP requests. By only decoding safe, unreserved characters (like letters, digits, and certain punctuation), the function prevents unintended changes to reserved characters (e.g., `?`, `&`, `=`) that have special meaning in URLs.
    
    Args:
        uri: The URI string containing percent-encoded sequences to process.
    
    Returns:
        A new URI string with unreserved percent-escape sequences decoded, while all other sequences remain encoded.
    """
    parts = uri.split("%")
    for i in range(1, len(parts)):
        h = parts[i][0:2]
        if len(h) == 2 and h.isalnum():
            try:
                c = chr(int(h, 16))
            except ValueError:
                raise InvalidURL(f"Invalid percent-escape sequence: '{h}'")

            if c in UNRESERVED_SET:
                parts[i] = c + parts[i][2:]
            else:
                parts[i] = f"%{parts[i]}"
        else:
            parts[i] = f"%{parts[i]}"
    return "".join(parts)


def requote_uri(uri):
    """
    Re-quote a URI to ensure consistent and correct URL encoding, particularly handling percent signs that may have been left unquoted.
    
    This function is used internally in Requests to normalize URIs after parsing or manipulation, ensuring that reserved characters and percent signs are properly encoded. This prevents issues when constructing or sending HTTP requests, especially when dealing with URLs containing special characters or malformed encoding.
    
    Args:
        uri: The URI string to re-quote
    
    Returns:
        A properly quoted URI string with consistent encoding, ensuring safe and correct HTTP request construction
    """
    safe_with_percent = "!#$%&'()*+,/:;=?@[]~"
    safe_without_percent = "!#$&'()*+,/:;=?@[]~"
    try:
        # Unquote only the unreserved characters
        # Then quote only illegal characters (do not quote reserved,
        # unreserved, or '%')
        return quote(unquote_unreserved(uri), safe=safe_with_percent)
    except InvalidURL:
        # We couldn't unquote the given URI, so let's try quoting it, but
        # there may be unquoted '%'s in the URI. We need to make sure they're
        # properly quoted so they do not cause issues elsewhere.
        return quote(uri, safe=safe_without_percent)


def address_in_network(ip, net):
    """
    Checks whether an IP address belongs to a specified network subnet, enabling network validation within HTTP client operations.
    
    This function is particularly useful in scenarios where Requests needs to determine if a target IP falls within a trusted or expected network range, such as when implementing network-based access controls or validating connectivity in secure environments.
    
    Args:
        ip: The IP address to check, in standard dotted-decimal notation (e.g., "192.168.1.1").
        net: The network subnet in CIDR notation (e.g., "192.168.1.0/24").
    
    Returns:
        True if the IP is within the specified network subnet; False otherwise.
    """
    ipaddr = struct.unpack("=L", socket.inet_aton(ip))[0]
    netaddr, bits = net.split("/")
    netmask = struct.unpack("=L", socket.inet_aton(dotted_netmask(int(bits))))[0]
    network = struct.unpack("=L", socket.inet_aton(netaddr))[0] & netmask
    return (ipaddr & netmask) == (network & netmask)


def dotted_netmask(mask):
    """
    Converts a CIDR notation subnet mask (e.g., /24) to its dotted decimal format (e.g., 255.255.255.0).
    
    This utility is used within Requests to support network configuration and IP address manipulation, particularly when working with network-related features such as proxy settings, IP filtering, or when interfacing with systems that require traditional netmask notation. The function enables consistent representation of subnet masks across different parts of the library.
    
    Returns:
        The dotted decimal representation of the subnet mask as a string.
    """
    bits = 0xFFFFFFFF ^ (1 << 32 - mask) - 1
    return socket.inet_ntoa(struct.pack(">I", bits))


def is_ipv4_address(string_ip):
    """
    Check if a given string is a valid IPv4 address.
    
    This function is used internally by Requests to validate IP addresses when handling network connections or DNS resolution. Ensuring the IP format is correct helps prevent errors during HTTP request setup, particularly when connecting directly to hosts via IP instead of domain names.
    
    Args:
        string_ip: The string to validate as an IPv4 address.
    
    Returns:
        True if the string is a valid IPv4 address, False otherwise.
    """
    try:
        socket.inet_aton(string_ip)
    except OSError:
        return False
    return True


def is_valid_cidr(string_network):
    """
    Validates whether a given string follows the CIDR (Classless Inter-Domain Routing) format used in the no_proxy environment variable.
    
    This check ensures that network addresses specified in no_proxy are properly formatted with a valid IP address and subnet mask (e.g., 192.168.1.0/24), which is essential for correctly excluding specific networks from proxy usage in HTTP requests. The validation confirms both the syntax and semantic correctness of the CIDR notation.
    
    Args:
        string_network: A string representing a network in CIDR format (e.g., '10.0.0.0/24').
    
    Returns:
        True if the string is a valid CIDR notation, False otherwise.
    """
    if string_network.count("/") == 1:
        try:
            mask = int(string_network.split("/")[1])
        except ValueError:
            return False

        if mask < 1 or mask > 32:
            return False

        try:
            socket.inet_aton(string_network.split("/")[0])
        except OSError:
            return False
    else:
        return False
    return True


@contextlib.contextmanager
def set_environ(env_name, value):
    """
    Temporarily set an environment variable for the duration of a context, preserving the original value.
    
    This is useful in testing or temporary configuration scenarios where you need to modify environment settings without affecting the global state. The function ensures that any changes are automatically reverted after the context exits, maintaining clean isolation—critical for reliable test suites and transient operations within Requests' ecosystem.
    
    Args:
        env_name: The name of the environment variable to modify.
        value: The value to set. If None, no changes are made.
    """
    value_changed = value is not None
    if value_changed:
        old_value = os.environ.get(env_name)
        os.environ[env_name] = value
    try:
        yield
    finally:
        if value_changed:
            if old_value is None:
                del os.environ[env_name]
            else:
                os.environ[env_name] = old_value


def should_bypass_proxies(url, no_proxy):
    """
    Determines whether a given URL should bypass configured proxies, based on the no_proxy environment variable or explicit no_proxy setting.
    
    This function is essential for maintaining security and network efficiency in Requests by ensuring that certain URLs—such as internal services or local resources—are not routed through external proxies. It checks both IP addresses and hostnames against the no_proxy list, supporting CIDR notation and port-aware matching.
    
    Args:
        url: The URL to evaluate for proxy bypass.
        no_proxy: Optional explicit no_proxy setting; if None, the function checks the NO_PROXY environment variable.
    
    Returns:
        True if the URL should bypass proxies, False otherwise.
    """

    # Prioritize lowercase environment variables over uppercase
    # to keep a consistent behaviour with other http projects (curl, wget).
    def get_proxy(key):
        return os.environ.get(key) or os.environ.get(key.upper())

    # First check whether no_proxy is defined. If it is, check that the URL
    # we're getting isn't in the no_proxy list.
    no_proxy_arg = no_proxy
    if no_proxy is None:
        no_proxy = get_proxy("no_proxy")
    parsed = urlparse(url)

    if parsed.hostname is None:
        # URLs don't always have hostnames, e.g. file:/// urls.
        return True

    if no_proxy:
        # We need to check whether we match here. We need to see if we match
        # the end of the hostname, both with and without the port.
        no_proxy = (host for host in no_proxy.replace(" ", "").split(",") if host)

        if is_ipv4_address(parsed.hostname):
            for proxy_ip in no_proxy:
                if is_valid_cidr(proxy_ip):
                    if address_in_network(parsed.hostname, proxy_ip):
                        return True
                elif parsed.hostname == proxy_ip:
                    # If no_proxy ip was defined in plain IP notation instead of cidr notation &
                    # matches the IP of the index
                    return True
        else:
            host_with_port = parsed.hostname
            if parsed.port:
                host_with_port += f":{parsed.port}"

            for host in no_proxy:
                if parsed.hostname.endswith(host) or host_with_port.endswith(host):
                    # The URL does match something in no_proxy, so we don't want
                    # to apply the proxies on this URL.
                    return True

    with set_environ("no_proxy", no_proxy_arg):
        # parsed.hostname can be `None` in cases such as a file URI.
        try:
            bypass = proxy_bypass(parsed.hostname)
        except (TypeError, socket.gaierror):
            bypass = False

    if bypass:
        return True

    return False


def get_environ_proxies(url, no_proxy=None):
    """
    Return a dictionary of proxy settings from environment variables, excluding proxies when the URL should be bypassed.
    
    This function determines whether to use system-provided proxy settings based on environment variables (like HTTP_PROXY, HTTPS_PROXY) and respects the NO_PROXY setting to avoid routing certain URLs through proxies. It's used internally by Requests to ensure that requests are routed correctly according to system configuration and security policies, helping maintain consistent and predictable network behavior across different environments.
    
    Args:
        url: The URL being requested, used to determine if proxies should be bypassed.
        no_proxy: Optional list of host patterns to exclude from proxy usage, typically derived from the NO_PROXY environment variable.
    
    Returns:
        A dictionary mapping protocol (http, https) to proxy URLs if proxies are configured and applicable; otherwise, an empty dictionary when bypassing proxies.
    """
    if should_bypass_proxies(url, no_proxy=no_proxy):
        return {}
    else:
        return getproxies()


def select_proxy(url, proxies):
    """
    Select an appropriate proxy for a given URL based on configured proxy settings.
    
    This function enables Requests to route HTTP requests through specified proxies when needed, supporting fine-grained control over proxy usage by scheme and host. It prioritizes specific proxy configurations (scheme://host), falls back to scheme-only proxies, and defaults to a global proxy if no specific match is found.
    
    Args:
        url: The URL being requested, used to determine the appropriate proxy based on scheme and hostname
        proxies: A dictionary mapping proxy schemes or scheme-host combinations to proxy URLs, or None to use no proxies
    
    Returns:
        The selected proxy URL if one matches the request, otherwise None
    """
    proxies = proxies or {}
    urlparts = urlparse(url)
    if urlparts.hostname is None:
        return proxies.get(urlparts.scheme, proxies.get("all"))

    proxy_keys = [
        urlparts.scheme + "://" + urlparts.hostname,
        urlparts.scheme,
        "all://" + urlparts.hostname,
        "all",
    ]
    proxy = None
    for proxy_key in proxy_keys:
        if proxy_key in proxies:
            proxy = proxies[proxy_key]
            break

    return proxy


def resolve_proxies(request, proxies, trust_env=True):
    """
    Resolves the appropriate proxy configuration for a given request by combining user-provided proxies with environment settings, while respecting NO_PROXY rules to avoid proxying certain destinations. This ensures secure and correct proxy usage in HTTP requests, which is essential for applications that need to route traffic through proxies while maintaining bypass rules for internal or sensitive domains.
    
    Args:
        request: The request object (or PreparedRequest) containing the URL to determine proxy settings for.
        proxies: A dictionary mapping URL schemes (e.g., 'http', 'https') or specific hosts to proxy URLs, or None.
        trust_env: Whether to consider system environment variables (like HTTP_PROXY, NO_PROXY) when determining proxy settings.
    
    Returns:
        A dictionary of proxy configurations for each scheme, updated with environment-provided proxies when applicable and bypassed according to NO_PROXY rules.
    """
    proxies = proxies if proxies is not None else {}
    url = request.url
    scheme = urlparse(url).scheme
    no_proxy = proxies.get("no_proxy")
    new_proxies = proxies.copy()

    if trust_env and not should_bypass_proxies(url, no_proxy=no_proxy):
        environ_proxies = get_environ_proxies(url, no_proxy=no_proxy)

        proxy = environ_proxies.get(scheme, environ_proxies.get("all"))

        if proxy:
            new_proxies.setdefault(scheme, proxy)
    return new_proxies


def default_user_agent(name="python-requests"):
    """
    Return a default user agent string used to identify requests made by the library.
    
    This helps server-side applications recognize traffic originating from Requests, which is useful for analytics, rate limiting, and debugging. The user agent includes the library name and version to provide transparency about the client making the request.
    
    Args:
        name: Custom identifier to include in the user agent (default: "python-requests")
    
    Returns:
        A formatted user agent string combining the provided name and the current library version
    """
    return f"{name}/{__version__}"


def default_headers():
    """
    Returns a set of default HTTP headers used by the Requests library to ensure consistent and efficient HTTP communication. These headers help identify the client, manage content encoding, and maintain persistent connections, aligning with best practices for web interactions.
    
    Returns:
        A CaseInsensitiveDict containing default headers including User-Agent, Accept-Encoding, Accept, and Connection.
    """
    return CaseInsensitiveDict(
        {
            "User-Agent": default_user_agent(),
            "Accept-Encoding": DEFAULT_ACCEPT_ENCODING,
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
    )


def parse_header_links(value):
    """
    Parse HTTP Link headers into a structured list of dictionaries for easy access to URLs and their associated parameters.
    
    Link headers are commonly used in HTTP responses to provide metadata about related resources, such as pagination links, alternate representations, or resource relationships. This function extracts and parses these links, making it easier for developers to navigate and utilize linked resources in API interactions.
    
    Args:
        value: A string containing one or more Link headers, formatted as per RFC 5988 (e.g., `<url>; rel=type; type="mime"`).
    
    Returns:
        A list of dictionaries, each containing a 'url' key and any additional parameters from the link (e.g., 'rel', 'type'), enabling straightforward access to linked resources in API clients.
    """

    links = []

    replace_chars = " '\""

    value = value.strip(replace_chars)
    if not value:
        return links

    for val in re.split(", *<", value):
        try:
            url, params = val.split(";", 1)
        except ValueError:
            url, params = val, ""

        link = {"url": url.strip("<> '\"")}

        for param in params.split(";"):
            try:
                key, value = param.split("=")
            except ValueError:
                break

            link[key.strip(replace_chars)] = value.strip(replace_chars)

        links.append(link)

    return links


# Null bytes; no need to recreate these on each call to guess_json_utf
_null = "\x00".encode("ascii")  # encoding to ASCII for Python 3
_null2 = _null * 2
_null3 = _null * 3


def guess_json_utf(data):
    """
    Guess the UTF encoding of JSON data based on byte patterns and BOM detection.
    
    This function helps Requests correctly decode JSON responses by identifying the underlying encoding
    when the content lacks explicit charset information. Since JSON always starts with ASCII characters,
    the presence and position of null bytes (0x00) and byte order marks (BOMs) can reliably indicate
    the encoding (UTF-8, UTF-16, or UTF-32). This ensures accurate parsing of JSON data regardless
    of the encoding used by the server, which is critical for robust HTTP response handling.
    """
    # JSON always starts with two ASCII characters, so detection is as
    # easy as counting the nulls and from their location and count
    # determine the encoding. Also detect a BOM, if present.
    sample = data[:4]
    if sample in (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE):
        return "utf-32"  # BOM included
    if sample[:3] == codecs.BOM_UTF8:
        return "utf-8-sig"  # BOM included, MS style (discouraged)
    if sample[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        return "utf-16"  # BOM included
    nullcount = sample.count(_null)
    if nullcount == 0:
        return "utf-8"
    if nullcount == 2:
        if sample[::2] == _null2:  # 1st and 3rd are null
            return "utf-16-be"
        if sample[1::2] == _null2:  # 2nd and 4th are null
            return "utf-16-le"
        # Did not detect 2 valid UTF-16 ascii-range characters
    if nullcount == 3:
        if sample[:3] == _null3:
            return "utf-32-be"
        if sample[1:] == _null3:
            return "utf-32-le"
        # Did not detect a valid UTF-32 ascii-range character
    return None


def prepend_scheme_if_needed(url, new_scheme):
    """
    Ensures a URL has a scheme by prepending the specified scheme if none is present, preserving existing schemes to maintain URL integrity.
    
    This function supports Requests' goal of simplifying HTTP interactions by handling malformed or incomplete URLs consistently, particularly when constructing requests from user-provided input that may lack a scheme (e.g., "example.com" instead of "https://example.com"). It maintains backward compatibility with legacy URL parsing behavior.
    
    Args:
        url: The URL string that may or may not include a scheme.
        new_scheme: The scheme to prepend if the URL lacks one (e.g., 'https').
    
    Returns:
        A URL string with the scheme added if missing, otherwise unchanged.
    """
    parsed = parse_url(url)
    scheme, auth, host, port, path, query, fragment = parsed

    # A defect in urlparse determines that there isn't a netloc present in some
    # urls. We previously assumed parsing was overly cautious, and swapped the
    # netloc and path. Due to a lack of tests on the original defect, this is
    # maintained with parse_url for backwards compatibility.
    netloc = parsed.netloc
    if not netloc:
        netloc, path = path, netloc

    if auth:
        # parse_url doesn't provide the netloc with auth
        # so we'll add it ourselves.
        netloc = "@".join([auth, netloc])
    if scheme is None:
        scheme = new_scheme
    if path is None:
        path = ""

    return urlunparse((scheme, netloc, path, "", query, fragment))


def get_auth_from_url(url):
    """
    Extract authentication credentials from a URL to support secure HTTP requests in the Requests library.
    
    This function enables the library to automatically parse and handle HTTP authentication details (username and password) embedded in URLs, which is essential for seamless authentication when making requests to protected resources. It ensures that credentials are properly decoded and returned in a usable format.
    
    Args:
        url: The URL string containing optional authentication components (e.g., `https://user:pass@example.com`).
    
    Returns:
        A tuple containing the decoded username and password as strings. If no authentication is present, returns ('', '').
    """
    parsed = urlparse(url)

    try:
        auth = (unquote(parsed.username), unquote(parsed.password))
    except (AttributeError, TypeError):
        auth = ("", "")

    return auth


def check_header_validity(header):
    """
    Validates HTTP header components to ensure they don't contain invalid characters that could compromise request integrity or cause parsing issues.
    
    Headers must not include leading whitespace, reserved characters, or control characters like returns, as these can lead to malformed requests or security vulnerabilities. This validation helps maintain compatibility with HTTP standards and ensures reliable communication with web servers.
    
    Args:
        header: Tuple containing (name, value) of the HTTP header to validate.
    
    Returns:
        True if both header name and value are valid; raises ValueError otherwise.
    """
    name, value = header
    _validate_header_part(header, name, 0)
    _validate_header_part(header, value, 1)


def _validate_header_part(header, header_part, header_validator_index):
    """
    Validates HTTP header names and values to ensure they conform to HTTP protocol standards, preventing malformed headers that could cause security issues or server rejection.
    
    Args:
        header: The name of the header being validated (used in error messages)
        header_part: The header part to validate, must be str or bytes
        header_validator_index: Index indicating whether validating header name (0) or value (1)
    
    Returns:
        None if validation passes; raises InvalidHeader if validation fails
    """
    if isinstance(header_part, str):
        validator = _HEADER_VALIDATORS_STR[header_validator_index]
    elif isinstance(header_part, bytes):
        validator = _HEADER_VALIDATORS_BYTE[header_validator_index]
    else:
        raise InvalidHeader(
            f"Header part ({header_part!r}) from {header} "
            f"must be of type str or bytes, not {type(header_part)}"
        )

    if not validator.match(header_part):
        header_kind = "name" if header_validator_index == 0 else "value"
        raise InvalidHeader(
            f"Invalid leading whitespace, reserved character(s), or return "
            f"character(s) in header {header_kind}: {header_part!r}"
        )


def urldefragauth(url):
    """
    Remove the fragment identifier and authentication credentials from a URL to produce a clean, standardized endpoint for HTTP requests.
    
    Args:
        url: The input URL containing optional fragment and authentication parts
    
    Returns:
        A cleaned URL with no fragment and without user credentials, suitable for consistent request handling in the Requests library
    """
    scheme, netloc, path, params, query, fragment = urlparse(url)

    # see func:`prepend_scheme_if_needed`
    if not netloc:
        netloc, path = path, netloc

    netloc = netloc.rsplit("@", 1)[-1]

    return urlunparse((scheme, netloc, path, params, query, ""))


def rewind_body(prepared_request):
    """
    Rewind the request body to its original position to enable re-reading during HTTP redirects.
    
    This is necessary because HTTP redirects require the request body to be resent, but the body stream may have been consumed during the initial request. By rewinding the file pointer to its recorded starting position, the body can be read again, ensuring the redirect request includes the full original payload. This maintains the integrity of the request when following redirects, which is essential for proper API and web service interactions.
    
    Args:
        prepared_request: The prepared request object containing the body stream and its recorded position.
    """
    body_seek = getattr(prepared_request.body, "seek", None)
    if body_seek is not None and isinstance(
        prepared_request._body_position, integer_types
    ):
        try:
            body_seek(prepared_request._body_position)
        except OSError:
            raise UnrewindableBodyError(
                "An error occurred when rewinding request body for redirect."
            )
    else:
        raise UnrewindableBodyError("Unable to rewind request body for redirect.")
