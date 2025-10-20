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
from typing import Any, Dict, Generator, IO, Iterable, Iterator, List, Mapping as TypingMapping, Optional, Tuple, Union

from urllib3.util import make_headers, parse_url

from . import certs
from .__version__ import __version__

# to_native_string is unused here, but imported here for backwards compatibility
# pylint: disable=unused-import
from ._internal_utils import (  # noqa: F401
    _HEADER_VALIDATORS_BYTE,
    _HEADER_VALIDATORS_STR,
    to_native_string,
)
# pylint: enable=unused-import
# pylint: disable=redefined-builtin
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
# pylint: enable=redefined-builtin
from .cookies import cookiejar_from_dict
from .exceptions import (
    FileModeWarning,
    InvalidHeader,
    InvalidURL,
    UnrewindableBodyError,
)
from .structures import CaseInsensitiveDict

NETRC_FILES = (".netrc", "_netrc")

DEFAULT_CA_BUNDLE_PATH: str = certs.where()  # type: ignore[attr-defined]

DEFAULT_PORTS = {"http": 80, "https": 443}

# Ensure that ', ' is used to preserve previous delimiter behavior.
DEFAULT_ACCEPT_ENCODING = ", ".join(
    re.split(r",\s*", make_headers(accept_encoding=True)["accept-encoding"])
)


if sys.platform == "win32":
    # provide a proxy_bypass version on Windows without DNS lookups

    def proxy_bypass_registry(host: str) -> bool:
        try:
            import winreg  # pylint: disable=import-outside-toplevel
        except ImportError:
            return False

        try:
            internet_settings = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            )
            # ProxyEnable could be REG_SZ or REG_DWORD, normalizing it
            proxy_enable = int(winreg.QueryValueEx(internet_settings, "ProxyEnable")[0])
            # ProxyOverride is almost always a string
            proxy_override = winreg.QueryValueEx(internet_settings, "ProxyOverride")[0]
        except (OSError, ValueError):
            return False
        if not proxy_enable or not proxy_override:
            return False

        # make a check value list from the registry entry: replace the
        # '<local>' string by the localhost entry and the corresponding
        # canonical entry.
        proxy_override = proxy_override.split(";")
        # filter out empty strings to avoid re.match return true in the following code.
        proxy_override = filter(None, proxy_override)
        # now check if we match one of the registry values.
        for test in proxy_override:
            if test == "<local>":
                if "." not in host:
                    return True
            test = test.replace(".", r"\.")  # mask dots
            test = test.replace("*", r".*")  # change glob sequence
            test = test.replace("?", r".")  # change glob char
            if re.match(test, host, re.I):
                return True
        return False

    def proxy_bypass(host: str) -> bool:  # type: ignore[misc] # noqa # pylint: disable=function-redefined
        """Return True, if the host should be bypassed.

        Checks proxy settings gathered from the environment, if specified,
        or the registry.
        """
        if getproxies_environment():
            result: bool = proxy_bypass_environment(host)
            return result
        return proxy_bypass_registry(host)


def dict_to_sequence(data: Union[TypingMapping[Any, Any], Iterable[Tuple[Any, Any]]]) -> Union[Iterable[Tuple[Any, Any]], TypingMapping[Any, Any]]:
    """Returns an internal sequence dictionary update."""

    if hasattr(data, "items"):
        data = data.items()

    return data


def super_len(obj: Any) -> Optional[int]:  # pylint: disable=too-many-branches
    """Calculate the length of a file-like object or string."""
    total_length: Optional[int] = None
    current_position: int = 0

    if not is_urllib3_1 and isinstance(obj, str):
        # urllib3 2.x+ treats all strings as utf-8 instead
        # of latin-1 (iso-8859-1) like http.client.
        obj = obj.encode("utf-8")

    if hasattr(obj, "__len__"):
        total_length = len(obj)

    elif hasattr(obj, "len"):
        total_length = obj.len

    elif hasattr(obj, "fileno"):
        try:
            fileno = obj.fileno()
        except (io.UnsupportedOperation, AttributeError):
            # AttributeError is a surprising exception, seeing as how we've just checked
            # that `hasattr(obj, 'fileno')`.  It happens for objects obtained via
            # `Tarfile.extractfile()`, per issue 5229.
            pass
        else:
            total_length = os.fstat(fileno).st_size

            # Having used fstat to determine the file length, we need to
            # confirm that this file was opened up in binary mode.
            if "b" not in obj.mode:
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

    if hasattr(obj, "tell"):
        try:
            current_position = obj.tell()
        except OSError:
            # This can happen in some weird situations, such as when the file
            # is actually a special file descriptor like stdin. In this
            # instance, we don't know what the length is, so set it to zero and
            # let requests chunk it instead.
            if total_length is not None:
                current_position = total_length
        else:
            if hasattr(obj, "seek") and total_length is None:
                # StringIO and BytesIO have seek but no usable fileno
                try:
                    # seek to end of file
                    obj.seek(0, 2)
                    total_length = obj.tell()

                    # seek back to current position to support
                    # partially read file-like objects
                    obj.seek(current_position or 0)
                except OSError:
                    total_length = 0

    if total_length is None:
        total_length = 0

    return max(0, total_length - current_position)


def get_netrc_auth(url: str, raise_errors: bool = False) -> Optional[Tuple[str, str]]:
    """Returns the Requests tuple auth for a given url from netrc."""

    netrc_file = os.environ.get("NETRC")
    if netrc_file is not None:
        netrc_locations: Tuple[str, ...] = (netrc_file,)
    else:
        netrc_locations = tuple(f"~/{netrc_file_name}" for netrc_file_name in NETRC_FILES)  # type: ignore[assignment]

    try:
        from netrc import NetrcParseError, netrc  # pylint: disable=import-outside-toplevel

        netrc_path: Optional[str] = None

        for netrc_location in netrc_locations:
            loc = os.path.expanduser(netrc_location)
            if os.path.exists(loc):
                netrc_path = loc
                break

        # Abort early if there isn't one.
        if netrc_path is None:
            return None

        parsed_url = urlparse(url)
        host = parsed_url.hostname

        try:
            _netrc = netrc(netrc_path).authenticators(host) if host else None
            if _netrc:
                # Return with login / password
                login_i = 0 if _netrc[0] else 1
                username: str = _netrc[login_i] or ""
                password: str = _netrc[2] or ""
                return (username, password)
        except (NetrcParseError, OSError):
            # If there was a parsing error or a permissions issue reading the file,
            # we'll just skip netrc auth unless explicitly asked to raise errors.
            if raise_errors:
                raise

    # App Engine hackiness.
    except (ImportError, AttributeError):
        pass

    return None


def guess_filename(obj: Any) -> Optional[str]:
    """Tries to guess the filename of the given object."""
    name = getattr(obj, "name", None)
    if name and isinstance(name, basestring) and name[0] != "<" and name[-1] != ">":
        result: str = os.path.basename(name)
        return result
    return None


def extract_zipped_paths(path: str) -> str:
    """Replace nonexistent paths that look like they refer to a member of a zip
    archive with the location of an extracted copy of the target, or else
    just return the provided path unchanged.
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

    with zipfile.ZipFile(archive) as zip_file:
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
def atomic_open(filename: str) -> Generator[IO[bytes], None, None]:
    """Write a file to the disk in an atomic fashion"""
    tmp_descriptor, tmp_name = tempfile.mkstemp(dir=os.path.dirname(filename))
    try:
        with os.fdopen(tmp_descriptor, "wb") as tmp_handler:
            yield tmp_handler
        os.replace(tmp_name, filename)
    except BaseException:
        os.remove(tmp_name)
        raise


def from_key_val_list(value: Any) -> Optional[OrderedDict[Any, Any]]:
    """Take an object and test to see if it can be represented as a
    dictionary. Unless it can not be represented as such, return an
    OrderedDict, e.g.,

    ::

        >>> from_key_val_list([('key', 'val')])
        OrderedDict([('key', 'val')])
        >>> from_key_val_list('string')
        Traceback (most recent call last):
        ...
        ValueError: cannot encode objects that are not 2-tuples
        >>> from_key_val_list({'key': 'val'})
        OrderedDict([('key', 'val')])

    :rtype: OrderedDict
    """
    if value is None:
        return None

    if isinstance(value, (str, bytes, bool, int)):
        raise ValueError("cannot encode objects that are not 2-tuples")

    return OrderedDict(value)


def to_key_val_list(value: Any) -> Optional[List[Tuple[Any, Any]]]:
    """Take an object and test to see if it can be represented as a
    dictionary. If it can be, return a list of tuples, e.g.,

    ::

        >>> to_key_val_list([('key', 'val')])
        [('key', 'val')]
        >>> to_key_val_list({'key': 'val'})
        [('key', 'val')]
        >>> to_key_val_list('string')
        Traceback (most recent call last):
        ...
        ValueError: cannot encode objects that are not 2-tuples

    :rtype: list
    """
    if value is None:
        return None

    if isinstance(value, (str, bytes, bool, int)):
        raise ValueError("cannot encode objects that are not 2-tuples")

    if isinstance(value, Mapping):
        value = value.items()

    return list(value)


# From mitsuhiko/werkzeug (used with permission).
def parse_list_header(value: str) -> List[str]:
    """Parse lists as described by RFC 2068 Section 2.

    In particular, parse comma-separated lists where the elements of
    the list may include quoted-strings.  A quoted-string could
    contain a comma.  A non-quoted string could have quotes in the
    middle.  Quotes are removed automatically after parsing.

    It basically works like :func:`parse_set_header` just that items
    may appear multiple times and case sensitivity is preserved.

    The return value is a standard :class:`list`:

    >>> parse_list_header('token, "quoted value"')
    ['token', 'quoted value']

    To create a header from the :class:`list` again, use the
    :func:`dump_header` function.

    :param value: a string with a list header.
    :return: :class:`list`
    :rtype: list
    """
    result: List[str] = []
    for item in _parse_list_header(value):
        if item[:1] == item[-1:] == '"':
            item = unquote_header_value(item[1:-1])
        result.append(item)
    return result


# From mitsuhiko/werkzeug (used with permission).
def parse_dict_header(value: str) -> Dict[str, Optional[str]]:
    """Parse lists of key, value pairs as described by RFC 2068 Section 2 and
    convert them into a python dict:

    >>> d = parse_dict_header('foo="is a fish", bar="as well"')
    >>> type(d) is dict
    True
    >>> sorted(d.items())
    [('bar', 'as well'), ('foo', 'is a fish')]

    If there is no value for a key it will be `None`:

    >>> parse_dict_header('key_without_value')
    {'key_without_value': None}

    To create a header from the :class:`dict` again, use the
    :func:`dump_header` function.

    :param value: a string with a dict header.
    :return: :class:`dict`
    :rtype: dict
    """
    result: Dict[str, Optional[str]] = {}
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
def unquote_header_value(value: str, is_filename: bool = False) -> str:
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


def dict_from_cookiejar(cookie_jar: Any) -> Dict[str, Any]:
    """Returns a key/value dictionary from a CookieJar.

    :param cookie_jar: CookieJar object to extract cookies from.
    :rtype: dict
    """

    cookie_dict: Dict[str, Any] = {cookie.name: cookie.value for cookie in cookie_jar}
    return cookie_dict


def add_dict_to_cookiejar(cookie_jar: Any, cookie_dict: Dict[str, Any]) -> Any:
    """Returns a CookieJar from a key/value dictionary.

    :param cookie_jar: CookieJar to insert cookies into.
    :param cookie_dict: Dict of key/values to insert into CookieJar.
    :rtype: CookieJar
    """

    return cookiejar_from_dict(cookie_dict, cookie_jar)


def get_encodings_from_content(content: str) -> List[str]:
    """Returns encodings from given content string.

    :param content: bytestring to extract encodings from.
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


def _parse_content_type_header(header: str) -> Tuple[str, Dict[str, Any]]:
    """Returns content type and parameters from given header

    :param header: string
    :return: tuple containing content type and dictionary of
         parameters
    """

    tokens = header.split(";")
    content_type, params = tokens[0].strip(), tokens[1:]
    params_dict: Dict[str, Any] = {}
    items_to_strip = "\"' "

    for param in params:
        param = param.strip()
        if param:
            key: str = param
            value: Any = True
            index_of_equals = param.find("=")
            if index_of_equals != -1:
                key = param[:index_of_equals].strip(items_to_strip)
                value = param[index_of_equals + 1 :].strip(items_to_strip)
            params_dict[key.lower()] = value
    return content_type, params_dict


def get_encoding_from_headers(headers: Any) -> Optional[str]:
    """Returns encodings from given HTTP Header Dict.

    :param headers: dictionary to extract encoding from.
    :rtype: str
    """

    content_type = headers.get("content-type")

    if not content_type:
        return None

    content_type, params = _parse_content_type_header(content_type)

    if "charset" in params:
        charset: str = params["charset"].strip("'\"")
        return charset

    if "text" in content_type:
        return "ISO-8859-1"

    if "application/json" in content_type:
        # Assume UTF-8 based on RFC 4627: https://www.ietf.org/rfc/rfc4627.txt since the charset was unset
        return "utf-8"

    return None


def stream_decode_response_unicode(iterator: Iterator[bytes], response: Any) -> Iterator[str]:
    """Stream decodes an iterator."""

    if response.encoding is None:
        yield from iterator  # type: ignore[misc]
        return

    decoder = codecs.getincrementaldecoder(response.encoding)(errors="replace")
    for chunk in iterator:
        decoded_chunk = decoder.decode(chunk)
        if decoded_chunk:
            yield decoded_chunk
    final_chunk = decoder.decode(b"", final=True)
    if final_chunk:
        yield final_chunk


def iter_slices(string: Union[str, bytes], slice_length: Optional[int]) -> Iterator[Union[str, bytes]]:
    """Iterate over slices of a string."""
    pos = 0
    if slice_length is None or slice_length <= 0:
        slice_length = len(string)
    while pos < len(string):
        yield string[pos : pos + slice_length]
        pos += slice_length


def get_unicode_from_response(response: Any) -> Any:
    """Returns the requested content back in unicode.

    :param response: Response object to get unicode content from.

    Tried:

    1. charset from content-type
    2. fall back and replace all unicode characters

    :rtype: str
    """
    warnings.warn(
        (
            "In requests 3.0, get_unicode_from_response will be removed. For "
            "more information, please see the discussion on issue #2266. (This"
            " warning should only appear once.)"
        ),
        DeprecationWarning,
    )

    tried_encodings: List[str] = []

    # Try charset from content-type
    encoding = get_encoding_from_headers(response.headers)

    if encoding:
        try:
            return str(response.content, encoding)
        except UnicodeError:
            tried_encodings.append(encoding)

    # Fall back:
    try:
        return str(response.content, encoding or "utf-8", errors="replace")
    except TypeError:
        return response.content


# The unreserved URI characters (RFC 3986)
UNRESERVED_SET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" + "0123456789-._~"
)


def unquote_unreserved(uri: str) -> str:
    """Un-escape any percent-escape sequences in a URI that are unreserved
    characters. This leaves all reserved, illegal and non-ASCII bytes encoded.

    :rtype: str
    """
    parts = uri.split("%")
    for i in range(1, len(parts)):
        hex_chars = parts[i][0:2]
        if len(hex_chars) == 2 and hex_chars.isalnum():
            try:
                char = chr(int(hex_chars, 16))
            except ValueError as exc:
                raise InvalidURL(f"Invalid percent-escape sequence: '{hex_chars}'") from exc

            if char in UNRESERVED_SET:
                parts[i] = char + parts[i][2:]
            else:
                parts[i] = f"%{parts[i]}"
        else:
            parts[i] = f"%{parts[i]}"
    return "".join(parts)


def requote_uri(uri: str) -> str:
    """Re-quote the given URI.

    This function passes the given URI through an unquote/quote cycle to
    ensure that it is fully and consistently quoted.

    :rtype: str
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


def address_in_network(ip_address: str, net: str) -> bool:
    """This function allows you to check if an IP belongs to a network subnet

    Example: returns True if ip_address = 192.168.1.1 and net = 192.168.1.0/24
             returns False if ip_address = 192.168.1.1 and net = 192.168.100.0/24

    :rtype: bool
    """
    ipaddr: int = struct.unpack("=L", socket.inet_aton(ip_address))[0]
    netaddr, bits = net.split("/")
    netmask: int = struct.unpack("=L", socket.inet_aton(dotted_netmask(int(bits))))[0]
    network: int = struct.unpack("=L", socket.inet_aton(netaddr))[0] & netmask
    result: bool = (ipaddr & netmask) == (network & netmask)
    return result


def dotted_netmask(mask: int) -> str:
    """Converts mask from /xx format to xxx.xxx.xxx.xxx

    Example: if mask is 24 function returns 255.255.255.0

    :rtype: str
    """
    bits = 0xFFFFFFFF ^ (1 << 32 - mask) - 1
    return socket.inet_ntoa(struct.pack(">I", bits))


def is_ipv4_address(string_ip: str) -> bool:
    """
    :rtype: bool
    """
    try:
        socket.inet_aton(string_ip)
    except OSError:
        return False
    return True


def is_valid_cidr(string_network: str) -> bool:
    """
    Very simple check of the cidr format in no_proxy variable.

    :rtype: bool
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
def set_environ(env_name: str, value: Optional[str]) -> Generator[None, None, None]:
    """Set the environment variable 'env_name' to 'value'

    Save previous value, yield, and then restore the previous value stored in
    the environment variable 'env_name'.

    If 'value' is None, do nothing"""
    value_changed = value is not None
    if value_changed:
        old_value = os.environ.get(env_name)
        os.environ[env_name] = value  # type: ignore[assignment]
    try:
        yield
    finally:
        if value_changed:
            if old_value is None:
                del os.environ[env_name]
            else:
                os.environ[env_name] = old_value


def _check_ipv4_in_no_proxy(hostname: str, no_proxy_list: List[str]) -> bool:
    """Check if IPv4 hostname matches any entry in no_proxy list."""
    for proxy_ip in no_proxy_list:
        if is_valid_cidr(proxy_ip):
            if address_in_network(hostname, proxy_ip):
                return True
        elif hostname == proxy_ip:
            # If no_proxy ip was defined in plain IP notation instead of cidr notation &
            # matches the IP of the index
            return True
    return False


def _check_hostname_in_no_proxy(hostname: str, port: Optional[int], no_proxy_list: List[str]) -> bool:
    """Check if hostname matches any entry in no_proxy list."""
    host_with_port = hostname
    if port:
        host_with_port += f":{port}"

    for host in no_proxy_list:
        if hostname.endswith(host) or host_with_port.endswith(host):
            # The URL does match something in no_proxy, so we don't want
            # to apply the proxies on this URL.
            return True
    return False


def should_bypass_proxies(url: str, no_proxy: Optional[str]) -> bool:
    """
    Returns whether we should bypass proxies or not.

    :rtype: bool
    """

    # Prioritize lowercase environment variables over uppercase
    # to keep a consistent behaviour with other http projects (curl, wget).
    def get_proxy(key: str) -> Optional[str]:
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
        no_proxy_list: List[str] = [host for host in no_proxy.replace(" ", "").split(",") if host]

        if is_ipv4_address(parsed.hostname):
            if _check_ipv4_in_no_proxy(parsed.hostname, no_proxy_list):
                return True
        else:
            if _check_hostname_in_no_proxy(parsed.hostname, parsed.port, no_proxy_list):
                return True

    with set_environ("no_proxy", no_proxy_arg):
        # parsed.hostname can be `None` in cases such as a file URI.
        try:
            bypass: bool = proxy_bypass(parsed.hostname)  # type: ignore[arg-type]
        except (TypeError, socket.gaierror):
            bypass = False

    return bypass


def get_environ_proxies(url: str, no_proxy: Optional[str] = None) -> Dict[str, str]:
    """
    Return a dict of environment proxies.

    :rtype: dict
    """
    if should_bypass_proxies(url, no_proxy=no_proxy):
        return {}
    return getproxies()


def select_proxy(url: str, proxies: Optional[Dict[str, str]]) -> Optional[str]:
    """Select a proxy for the url, if applicable.

    :param url: The url being for the request
    :param proxies: A dictionary of schemes or schemes and hosts to proxy URLs
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
    proxy: Optional[str] = None
    for proxy_key in proxy_keys:
        if proxy_key in proxies:
            proxy = proxies[proxy_key]
            break

    return proxy


def resolve_proxies(request: Any, proxies: Optional[Dict[str, str]], trust_env: bool = True) -> Dict[str, str]:
    """This method takes proxy information from a request and configuration
    input to resolve a mapping of target proxies. This will consider settings
    such as NO_PROXY to strip proxy configurations.

    :param request: Request or PreparedRequest
    :param proxies: A dictionary of schemes or schemes and hosts to proxy URLs
    :param trust_env: Boolean declaring whether to trust environment configs

    :rtype: dict
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


def default_user_agent(name: str = "python-requests") -> str:
    """
    Return a string representing the default user agent.

    :rtype: str
    """
    return f"{name}/{__version__}"


def default_headers() -> CaseInsensitiveDict:
    """
    :rtype: requests.structures.CaseInsensitiveDict
    """
    return CaseInsensitiveDict(
        {
            "User-Agent": default_user_agent(),
            "Accept-Encoding": DEFAULT_ACCEPT_ENCODING,
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
    )


def parse_header_links(value: str) -> List[Dict[str, str]]:
    """Return a list of parsed link headers proxies.

    i.e. Link: <http:/.../front.jpeg>; rel=front; type="image/jpeg",<http://.../back.jpeg>; rel=back;type="image/jpeg"

    :rtype: list
    """

    links: List[Dict[str, str]] = []

    replace_chars = " '\""

    value = value.strip(replace_chars)
    if not value:
        return links

    for val in re.split(", *<", value):
        try:
            url, params = val.split(";", 1)
        except ValueError:
            url, params = val, ""

        link: Dict[str, str] = {"url": url.strip("<> '\"")}

        for param in params.split(";"):
            try:
                key, value = param.split("=")
            except ValueError:
                break

            link[key.strip(replace_chars)] = value.strip(replace_chars)

        links.append(link)

    return links


# Null bytes; no need to recreate these on each call to guess_json_utf
_NULL = "\x00".encode("ascii")  # encoding to ASCII for Python 3
_NULL2 = _NULL * 2
_NULL3 = _NULL * 3


def guess_json_utf(data: bytes) -> Optional[str]:  # pylint: disable=too-many-return-statements
    """
    :rtype: str
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
    nullcount = sample.count(_NULL)
    if not nullcount:
        return "utf-8"
    if nullcount == 2:
        if sample[::2] == _NULL2:  # 1st and 3rd are null
            return "utf-16-be"
        if sample[1::2] == _NULL2:  # 2nd and 4th are null
            return "utf-16-le"
        # Did not detect 2 valid UTF-16 ascii-range characters
    if nullcount == 3:
        if sample[:3] == _NULL3:
            return "utf-32-be"
        if sample[1:] == _NULL3:
            return "utf-32-le"
        # Did not detect a valid UTF-32 ascii-range character
    return None


def prepend_scheme_if_needed(url: str, new_scheme: str) -> str:
    """Given a URL that may or may not have a scheme, prepend the given scheme.
    Does not replace a present scheme with the one provided as an argument.

    :rtype: str
    """
    parsed = parse_url(url)
    scheme, auth, _host, _port, path, query, _fragment = parsed

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
        netloc = "@".join([auth or "", netloc or ""])
    if scheme is None:
        scheme = new_scheme
    if path is None:
        path = ""

    return urlunparse((scheme, netloc, path, "", query, _fragment))


def get_auth_from_url(url: str) -> Tuple[str, str]:
    """Given a url with authentication components, extract them into a tuple of
    username,password.

    :rtype: (str,str)
    """
    parsed = urlparse(url)

    try:
        auth = (unquote(parsed.username), unquote(parsed.password))  # type: ignore[arg-type]
    except (AttributeError, TypeError):
        auth = ("", "")

    return auth


def check_header_validity(header: Tuple[Any, Any]) -> None:
    """Verifies that header parts don't contain leading whitespace
    reserved characters, or return characters.

    :param header: tuple, in the format (name, value).
    """
    name, value = header
    _validate_header_part(header, name, 0)
    _validate_header_part(header, value, 1)


def _validate_header_part(header: Tuple[Any, Any], header_part: Union[str, bytes], header_validator_index: int) -> None:
    if isinstance(header_part, str):
        validator = _HEADER_VALIDATORS_STR[header_validator_index]
        if not validator.match(header_part):
            header_kind = "name" if not header_validator_index else "value"
            raise InvalidHeader(
                f"Invalid leading whitespace, reserved character(s), or return "
                f"character(s) in header {header_kind}: {header_part!r}"
            )
    elif isinstance(header_part, bytes):
        validator_bytes = _HEADER_VALIDATORS_BYTE[header_validator_index]
        if not validator_bytes.match(header_part):
            header_kind = "name" if not header_validator_index else "value"
            raise InvalidHeader(
                f"Invalid leading whitespace, reserved character(s), or return "
                f"character(s) in header {header_kind}: {header_part!r}"
            )
    else:
        raise InvalidHeader(
            f"Header part ({header_part!r}) from {header} "
            f"must be of type str or bytes, not {type(header_part)}"
        )


def urldefragauth(url: str) -> str:
    """
    Given a url remove the fragment and the authentication part.

    :rtype: str
    """
    scheme, netloc, path, params, query, _fragment = urlparse(url)

    # see func:`prepend_scheme_if_needed`
    if not netloc:
        netloc, path = path, netloc

    netloc = netloc.rsplit("@", 1)[-1]

    return urlunparse((scheme, netloc, path, params, query, ""))


def rewind_body(prepared_request: Any) -> None:
    """Move file pointer back to its recorded starting position
    so it can be read again on redirect.
    """
    body_seek = getattr(prepared_request.body, "seek", None)
    # pylint: disable=protected-access
    if body_seek is not None and isinstance(
        prepared_request._body_position, integer_types
    ):
        try:
            body_seek(prepared_request._body_position)
        except OSError as exc:
            raise UnrewindableBodyError(
                "An error occurred when rewinding request body for redirect."
            ) from exc
    # pylint: enable=protected-access
    else:
        raise UnrewindableBodyError("Unable to rewind request body for redirect.")
