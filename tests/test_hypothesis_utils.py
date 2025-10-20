"""
Hypothesis-based property tests for requests.utils module.

These tests use property-based testing to automatically generate test cases
and find edge cases that might not be caught by traditional example-based tests.
"""

import codecs
import os
import socket
import struct
from collections import OrderedDict
from io import BytesIO, StringIO

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from requests.exceptions import InvalidURL
from requests.structures import CaseInsensitiveDict
from requests.utils import (
    _parse_content_type_header,
    address_in_network,
    dotted_netmask,
    from_key_val_list,
    get_encoding_from_headers,
    guess_json_utf,
    is_ipv4_address,
    is_valid_cidr,
    iter_slices,
    parse_dict_header,
    parse_header_links,
    parse_list_header,
    prepend_scheme_if_needed,
    requote_uri,
    super_len,
    to_key_val_list,
    unquote_header_value,
    unquote_unreserved,
    urldefragauth,
)


class TestSuperLenProperties:
    """Property-based tests for super_len function."""

    @given(st.text(alphabet=st.characters(max_codepoint=127)))
    def test_super_len_string_equals_len(self, s: str) -> None:
        """super_len of an ASCII string should equal its byte length when encoded."""
        # Note: In urllib3 2.x+, strings are treated as UTF-8 for length calculation
        expected = len(s.encode("utf-8"))
        assert super_len(s) == expected

    @given(st.binary())
    def test_super_len_bytes_equals_len(self, b: bytes) -> None:
        """super_len of bytes should equal its length."""
        assert super_len(b) == len(b)

    @given(st.lists(st.integers()))
    def test_super_len_list_equals_len(self, lst: list) -> None:
        """super_len of a list should equal its length."""
        assert super_len(lst) == len(lst)

    @given(st.binary())
    def test_super_len_bytesio_equals_len(self, data: bytes) -> None:
        """super_len of BytesIO should equal data length."""
        bio = BytesIO(data)
        assert super_len(bio) == len(data)

    @given(st.binary())
    def test_super_len_bytesio_partially_read(self, data: bytes) -> None:
        """super_len should account for partially read BytesIO."""
        assume(len(data) > 1)
        bio = BytesIO(data)
        # Read some bytes
        read_amount = len(data) // 2
        bio.read(read_amount)
        remaining = len(data) - read_amount
        assert super_len(bio) == remaining

    @given(st.text())
    def test_super_len_stringio(self, s: str) -> None:
        """super_len of StringIO should equal string length."""
        sio = StringIO(s)
        assert super_len(sio) == len(s)


class TestKeyValListProperties:
    """Property-based tests for key-value list conversion functions."""

    @given(st.lists(st.tuples(st.text(min_size=1), st.text())))
    def test_to_key_val_list_from_list(
        self, items: list[tuple[str, str]]
    ) -> None:
        """to_key_val_list should preserve list of tuples."""
        result = to_key_val_list(items)
        assert result == items

    @given(st.dictionaries(st.text(min_size=1), st.text()))
    def test_to_key_val_list_from_dict(self, d: dict) -> None:
        """to_key_val_list should convert dict to list of tuples."""
        result = to_key_val_list(d)
        assert isinstance(result, list)
        assert set(result) == set(d.items())

    @given(st.none())
    def test_to_key_val_list_none(self, value: None) -> None:
        """to_key_val_list should return None for None input."""
        assert to_key_val_list(value) is None

    @given(st.one_of(st.text(), st.integers(), st.booleans()))
    def test_to_key_val_list_invalid_types(self, value) -> None:
        """to_key_val_list should raise ValueError for invalid types."""
        with pytest.raises(ValueError):
            to_key_val_list(value)

    @given(st.lists(st.tuples(st.text(min_size=1), st.text()), unique_by=lambda x: x[0]))
    def test_from_key_val_list_returns_ordered_dict(
        self, items: list[tuple[str, str]]
    ) -> None:
        """from_key_val_list should return OrderedDict."""
        result = from_key_val_list(items)
        assert isinstance(result, OrderedDict)
        # OrderedDict collapses duplicate keys, so check length and values
        assert len(result) == len(items)
        for key, value in items:
            assert result[key] == value

    @given(st.dictionaries(st.text(min_size=1), st.text()))
    def test_from_key_val_list_from_dict(self, d: dict) -> None:
        """from_key_val_list should work with dict input."""
        result = from_key_val_list(d)
        assert isinstance(result, OrderedDict)
        assert dict(result) == d

    @given(st.none())
    def test_from_key_val_list_none(self, value: None) -> None:
        """from_key_val_list should return None for None input."""
        assert from_key_val_list(value) is None

    @given(st.one_of(st.text(), st.integers(), st.booleans()))
    def test_from_key_val_list_invalid_types(self, value) -> None:
        """from_key_val_list should raise ValueError for invalid types."""
        with pytest.raises(ValueError):
            from_key_val_list(value)

    @given(st.lists(st.tuples(st.text(min_size=1), st.text()), unique_by=lambda x: x[0]))
    def test_roundtrip_to_from_key_val_list(
        self, items: list[tuple[str, str]]
    ) -> None:
        """Converting to dict and back should preserve data (with unique keys)."""
        result = to_key_val_list(from_key_val_list(items))
        # Result should be equal to items (since we have unique keys)
        assert result == items


class TestUnquoteHeaderValueProperties:
    """Property-based tests for unquote_header_value function."""

    @given(st.text(min_size=1))
    def test_unquote_non_quoted_unchanged(self, value: str) -> None:
        """Unquoted values without surrounding quotes should be unchanged."""
        assume(not (value.startswith('"') and value.endswith('"')))
        assert unquote_header_value(value) == value

    @given(st.text())
    def test_unquote_quoted_removes_quotes(self, value: str) -> None:
        """Quoted values should have quotes removed."""
        quoted = f'"{value}"'
        result = unquote_header_value(quoted)
        # The function also processes escape sequences
        assert not (result.startswith('"') and result.endswith('"'))

    @given(st.none())
    def test_unquote_none(self, value: None) -> None:
        """None input should return None."""
        assert unquote_header_value(value) is None


class TestIPv4Properties:
    """Property-based tests for IPv4 address validation."""

    @given(
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
    )
    def test_valid_ipv4_address(
        self, a: int, b: int, c: int, d: int
    ) -> None:
        """Valid IPv4 addresses should be recognized."""
        ip = f"{a}.{b}.{c}.{d}"
        assert is_ipv4_address(ip)

    @given(st.text().filter(lambda x: "." not in x and not x.isdigit() and "\x00" not in x))
    def test_invalid_ipv4_no_dots(self, value: str) -> None:
        """Strings without dots (except single numbers) should not be valid IPv4."""
        # Note: Single numbers like "0" are valid shorthand IPs
        # Also filter out null characters which cause ValueError
        assert not is_ipv4_address(value)

    @given(st.integers(min_value=1, max_value=32))
    def test_dotted_netmask_valid_range(self, mask: int) -> None:
        """dotted_netmask should work for valid mask values."""
        result = dotted_netmask(mask)
        parts = result.split(".")
        assert len(parts) == 4
        assert all(0 <= int(p) <= 255 for p in parts)

    @given(
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=1, max_value=32),
    )
    def test_valid_cidr(
        self, a: int, b: int, c: int, d: int, mask: int
    ) -> None:
        """Valid CIDR notation should be recognized."""
        cidr = f"{a}.{b}.{c}.{d}/{mask}"
        assert is_valid_cidr(cidr)

    @given(st.text())
    def test_invalid_cidr_no_slash(self, value: str) -> None:
        """CIDR without slash should be invalid."""
        assume("/" not in value)
        assert not is_valid_cidr(value)

    @given(
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=33, max_value=100),
    )
    def test_invalid_cidr_mask_too_large(
        self, a: int, b: int, c: int, d: int, mask: int
    ) -> None:
        """CIDR with mask > 32 should be invalid."""
        cidr = f"{a}.{b}.{c}.{d}/{mask}"
        assert not is_valid_cidr(cidr)


class TestIterSlicesProperties:
    """Property-based tests for iter_slices function."""

    @given(st.text(), st.integers(min_value=1, max_value=100))
    def test_iter_slices_covers_all_content(
        self, text: str, slice_length: int
    ) -> None:
        """iter_slices should return all content when joined."""
        result = "".join(iter_slices(text, slice_length))
        assert result == text

    @given(st.binary(), st.integers(min_value=1, max_value=100))
    def test_iter_slices_bytes_covers_all(
        self, data: bytes, slice_length: int
    ) -> None:
        """iter_slices should return all bytes content when joined."""
        result = b"".join(iter_slices(data, slice_length))
        assert result == data

    @given(st.text(min_size=1), st.integers(min_value=1, max_value=10))
    def test_iter_slices_max_slice_size(
        self, text: str, slice_length: int
    ) -> None:
        """No slice should exceed the specified length."""
        slices = list(iter_slices(text, slice_length))
        for s in slices[:-1]:  # All but last
            assert len(s) == slice_length
        # Last slice can be shorter
        if slices:
            assert len(slices[-1]) <= slice_length

    @given(st.text(min_size=1))
    def test_iter_slices_none_length(self, text: str) -> None:
        """None or invalid slice_length should return full string (non-empty)."""
        result = list(iter_slices(text, None))
        assert len(result) == 1
        assert result[0] == text

    @given(st.text(min_size=1))
    def test_iter_slices_zero_length(self, text: str) -> None:
        """Zero slice_length should return full string (non-empty)."""
        result = list(iter_slices(text, 0))
        assert len(result) == 1
        assert result[0] == text

    @given(st.text(min_size=1))
    def test_iter_slices_negative_length(self, text: str) -> None:
        """Negative slice_length should return full string (non-empty)."""
        result = list(iter_slices(text, -1))
        assert len(result) == 1
        assert result[0] == text


class TestGuessJSONUTFProperties:
    """Property-based tests for guess_json_utf function."""

    @given(st.sampled_from(["utf-8", "utf-16", "utf-32"]))
    def test_guess_json_utf_recognizes_encoding(
        self, encoding: str
    ) -> None:
        """guess_json_utf should recognize common JSON encodings."""
        data = "{}".encode(encoding)
        result = guess_json_utf(data)
        # Result should be related to the encoding
        assert result is not None
        assert encoding.split("-")[0] in result

    @given(st.binary(min_size=4, max_size=4))
    def test_guess_json_utf_returns_string_or_none(
        self, data: bytes
    ) -> None:
        """guess_json_utf should return str or None."""
        result = guess_json_utf(data)
        assert result is None or isinstance(result, str)


class TestURLDefragAuthProperties:
    """Property-based tests for urldefragauth function."""

    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=20,
        ),
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=20,
        ),
    )
    def test_urldefragauth_removes_fragment(
        self, path: str, fragment: str
    ) -> None:
        """urldefragauth should remove fragments."""
        url = f"http://example.com/{path}#{fragment}"
        result = urldefragauth(url)
        assert "#" not in result

    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=5,
            max_size=20,
        ),
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=5,
            max_size=20,
        ),
    )
    def test_urldefragauth_removes_auth(
        self, user: str, password: str
    ) -> None:
        """urldefragauth should remove authentication."""
        # Use longer strings to avoid substring collisions with domain
        assume("example" not in user and "example" not in password)
        assume("com" not in user and "com" not in password)
        assume("path" not in user and "path" not in password)
        url = f"http://{user}:{password}@example.com/path"
        result = urldefragauth(url)
        # Check that the auth part is removed (@ should not be in result)
        assert "@" not in result or not result.startswith("http://")


class TestRequoteURIProperties:
    """Property-based tests for requote_uri function."""

    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=100,
        )
    )
    def test_requote_uri_idempotent(self, path: str) -> None:
        """requote_uri should be idempotent for safe strings."""
        url = f"http://example.com/{path}"
        first = requote_uri(url)
        second = requote_uri(first)
        assert first == second

    @given(st.text(min_size=1))
    def test_requote_uri_returns_string(self, path: str) -> None:
        """requote_uri should always return a string."""
        try:
            url = f"http://example.com/{path}"
            result = requote_uri(url)
            assert isinstance(result, str)
        except InvalidURL:
            # Some paths may cause InvalidURL, which is acceptable
            pass


class TestUnquoteUnreservedProperties:
    """Property-based tests for unquote_unreserved function."""

    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=50,
        )
    )
    def test_unquote_unreserved_returns_string(self, uri: str) -> None:
        """unquote_unreserved should return a string."""
        try:
            result = unquote_unreserved(uri)
            assert isinstance(result, str)
        except InvalidURL:
            # Invalid percent-escape sequences may raise InvalidURL
            pass

    @given(
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
            min_size=1,
            max_size=50,
        )
    )
    def test_unquote_unreserved_unreserved_chars_unchanged(
        self, uri: str
    ) -> None:
        """Unreserved characters should remain unchanged."""
        result = unquote_unreserved(uri)
        assert result == uri


class TestPreprendSchemeIfNeededProperties:
    """Property-based tests for prepend_scheme_if_needed function."""

    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=50,
        )
    )
    def test_prepend_scheme_adds_scheme_if_missing(
        self, domain: str
    ) -> None:
        """prepend_scheme_if_needed should add scheme if missing."""
        url = f"{domain}.com/path"
        result = prepend_scheme_if_needed(url, "http")
        assert result.startswith("http://")

    @given(
        st.sampled_from(["http", "https", "ftp"]),
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=50,
        ),
    )
    def test_prepend_scheme_preserves_existing_scheme(
        self, scheme: str, domain: str
    ) -> None:
        """prepend_scheme_if_needed should not replace existing scheme."""
        url = f"{scheme}://{domain}.com/path"
        result = prepend_scheme_if_needed(url, "ftp")
        assert result.startswith(f"{scheme}://")


class TestParseHeaderLinksProperties:
    """Property-based tests for parse_header_links function."""

    @given(st.text(min_size=0, max_size=0))
    def test_parse_header_links_empty_string(self, value: str) -> None:
        """Empty string should return empty list."""
        assert parse_header_links(value) == []

    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=100,
        )
    )
    def test_parse_header_links_returns_list(self, url: str) -> None:
        """parse_header_links should return a list."""
        link = f"<http://{url}.com>"
        result = parse_header_links(link)
        assert isinstance(result, list)


class TestParseDictHeaderProperties:
    """Property-based tests for parse_dict_header function."""

    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=20,
        ),
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=20,
        ),
    )
    def test_parse_dict_header_simple_pair(
        self, key: str, value: str
    ) -> None:
        """parse_dict_header should parse simple key=value pairs (ASCII only)."""
        header = f'{key}="{value}"'
        result = parse_dict_header(header)
        assert isinstance(result, dict)
        assert key in result

    @given(st.text(min_size=1, max_size=20))
    def test_parse_dict_header_no_value(self, key: str) -> None:
        """parse_dict_header should handle keys without values."""
        assume("=" not in key and "," not in key)
        result = parse_dict_header(key)
        assert isinstance(result, dict)
        assert result.get(key) is None


class TestParseListHeaderProperties:
    """Property-based tests for parse_list_header function."""

    @given(
        st.lists(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=20,
            ),
            min_size=1,
            max_size=10,
        )
    )
    def test_parse_list_header_returns_list(self, items: list[str]) -> None:
        """parse_list_header should return a list."""
        header = ", ".join(items)
        result = parse_list_header(header)
        assert isinstance(result, list)
        assert len(result) == len(items)


class TestParseContentTypeHeaderProperties:
    """Property-based tests for _parse_content_type_header function."""

    @given(
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyz/",
            min_size=3,
            max_size=30,
        )
    )
    def test_parse_content_type_header_returns_tuple(
        self, content_type: str
    ) -> None:
        """_parse_content_type_header should return a tuple."""
        result = _parse_content_type_header(content_type)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], str)
        assert isinstance(result[1], dict)

    @given(
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyz/",
            min_size=3,
            max_size=30,
        ),
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyz-",
            min_size=1,
            max_size=20,
        ),
    )
    def test_parse_content_type_header_with_charset(
        self, content_type: str, charset: str
    ) -> None:
        """_parse_content_type_header should parse charset parameter."""
        header = f"{content_type}; charset={charset}"
        result = _parse_content_type_header(header)
        assert isinstance(result[1], dict)
        if "charset" in result[1]:
            assert isinstance(result[1]["charset"], (str, bool))


class TestGetEncodingFromHeadersProperties:
    """Property-based tests for get_encoding_from_headers function."""

    @given(st.dictionaries(st.text(), st.text()))
    def test_get_encoding_from_headers_with_caseinsensitive_dict(
        self, headers_dict: dict
    ) -> None:
        """get_encoding_from_headers should work with CaseInsensitiveDict."""
        headers = CaseInsensitiveDict(headers_dict)
        result = get_encoding_from_headers(headers)
        assert result is None or isinstance(result, str)

    @given(
        st.sampled_from(
            ["utf-8", "iso-8859-1", "utf-16", "ascii", "windows-1252"]
        )
    )
    def test_get_encoding_from_headers_with_valid_charset(
        self, charset: str
    ) -> None:
        """get_encoding_from_headers should extract valid charsets."""
        headers = CaseInsensitiveDict(
            {"content-type": f"text/html; charset={charset}"}
        )
        result = get_encoding_from_headers(headers)
        assert result == charset

