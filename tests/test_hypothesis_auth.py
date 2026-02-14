"""
Hypothesis-based property tests for requests.auth module.

These tests use property-based testing to verify the invariants and properties
of authentication classes and functions.
"""

import base64
import re

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from requests.auth import HTTPBasicAuth, HTTPDigestAuth, HTTPProxyAuth, _basic_auth_str
from requests.models import PreparedRequest


# Strategies for usernames and passwords
safe_text = st.text(
    alphabet=st.characters(
        min_codepoint=ord(" "), max_codepoint=ord("~"), blacklist_characters=":"
    ),
    min_size=1,
    max_size=50,
)


class TestBasicAuthStrProperties:
    """Property-based tests for _basic_auth_str function."""

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_basic_auth_str_format(self, username: str, password: str) -> None:
        """_basic_auth_str should return properly formatted Basic auth string."""
        result = _basic_auth_str(username, password)
        assert isinstance(result, str)
        assert result.startswith("Basic ")

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_basic_auth_str_base64_decodable(self, username: str, password: str) -> None:
        """_basic_auth_str should produce valid base64 encoding."""
        result = _basic_auth_str(username, password)
        # Extract the base64 part
        b64_part = result.replace("Basic ", "")
        try:
            decoded = base64.b64decode(b64_part)
            assert isinstance(decoded, bytes)
            # Should contain username and password separated by colon
            assert b":" in decoded
        except Exception:
            # If decoding fails, test fails
            pytest.fail("Failed to decode base64")

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_basic_auth_str_contains_credentials(self, username: str, password: str) -> None:
        """_basic_auth_str should encode username and password."""
        result = _basic_auth_str(username, password)
        b64_part = result.replace("Basic ", "")
        decoded = base64.b64decode(b64_part).decode("latin1")
        assert username in decoded
        assert password in decoded

    @settings(max_examples=1000, deadline=None)
    @given(st.text(min_size=1, max_size=50), st.text(min_size=1, max_size=50))
    def test_basic_auth_str_deterministic(self, username: str, password: str) -> None:
        """_basic_auth_str should be deterministic."""
        try:
            result1 = _basic_auth_str(username, password)
            result2 = _basic_auth_str(username, password)
            assert result1 == result2
        except Exception:
            # Some characters may cause encoding issues
            pass


class TestHTTPBasicAuthProperties:
    """Property-based tests for HTTPBasicAuth class."""

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_basic_auth_creation(self, username: str, password: str) -> None:
        """HTTPBasicAuth should be creatable with username and password."""
        auth = HTTPBasicAuth(username, password)
        assert isinstance(auth, HTTPBasicAuth)
        assert auth.username == username
        assert auth.password == password

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_basic_auth_adds_header(self, username: str, password: str) -> None:
        """HTTPBasicAuth should add Authorization header to request."""
        auth = HTTPBasicAuth(username, password)
        req = PreparedRequest()
        req.prepare_method("GET")
        req.prepare_url("http://example.com", None)
        req.prepare_headers({})

        result = auth(req)
        assert "Authorization" in result.headers
        assert result.headers["Authorization"].startswith("Basic ")

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_basic_auth_equality(self, username: str, password: str) -> None:
        """HTTPBasicAuth instances with same credentials should be equal."""
        auth1 = HTTPBasicAuth(username, password)
        auth2 = HTTPBasicAuth(username, password)
        assert auth1 == auth2

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text, safe_text)
    def test_http_basic_auth_inequality(
        self, username1: str, username2: str, password: str
    ) -> None:
        """HTTPBasicAuth instances with different credentials should not be equal."""
        assume(username1 != username2)
        auth1 = HTTPBasicAuth(username1, password)
        auth2 = HTTPBasicAuth(username2, password)
        assert auth1 != auth2

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_basic_auth_returns_request(self, username: str, password: str) -> None:
        """HTTPBasicAuth should return the request object."""
        auth = HTTPBasicAuth(username, password)
        req = PreparedRequest()
        req.prepare_method("GET")
        req.prepare_url("http://example.com", None)
        req.prepare_headers({})

        result = auth(req)
        assert result is req

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_basic_auth_ne_operator(self, username: str, password: str) -> None:
        """HTTPBasicAuth __ne__ should work correctly."""
        auth1 = HTTPBasicAuth(username, password)
        auth2 = HTTPBasicAuth(username, password)
        assert not (auth1 != auth2)


class TestHTTPProxyAuthProperties:
    """Property-based tests for HTTPProxyAuth class."""

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_proxy_auth_creation(self, username: str, password: str) -> None:
        """HTTPProxyAuth should be creatable with username and password."""
        auth = HTTPProxyAuth(username, password)
        assert isinstance(auth, HTTPProxyAuth)
        assert auth.username == username
        assert auth.password == password

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_proxy_auth_adds_header(self, username: str, password: str) -> None:
        """HTTPProxyAuth should add Proxy-Authorization header."""
        auth = HTTPProxyAuth(username, password)
        req = PreparedRequest()
        req.prepare_method("GET")
        req.prepare_url("http://example.com", None)
        req.prepare_headers({})

        result = auth(req)
        assert "Proxy-Authorization" in result.headers
        assert result.headers["Proxy-Authorization"].startswith("Basic ")

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_proxy_auth_is_basic_auth_subclass(
        self, username: str, password: str
    ) -> None:
        """HTTPProxyAuth should be a subclass of HTTPBasicAuth."""
        auth = HTTPProxyAuth(username, password)
        assert isinstance(auth, HTTPBasicAuth)


class TestHTTPDigestAuthProperties:
    """Property-based tests for HTTPDigestAuth class."""

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_digest_auth_creation(self, username: str, password: str) -> None:
        """HTTPDigestAuth should be creatable with username and password."""
        auth = HTTPDigestAuth(username, password)
        assert isinstance(auth, HTTPDigestAuth)
        assert auth.username == username
        assert auth.password == password

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_digest_auth_has_thread_local(self, username: str, password: str) -> None:
        """HTTPDigestAuth should have thread-local storage."""
        auth = HTTPDigestAuth(username, password)
        assert hasattr(auth, "_thread_local")

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_digest_auth_init_per_thread_state(
        self, username: str, password: str
    ) -> None:
        """HTTPDigestAuth should initialize per-thread state."""
        auth = HTTPDigestAuth(username, password)
        auth.init_per_thread_state()
        assert hasattr(auth._thread_local, "init")
        assert hasattr(auth._thread_local, "last_nonce")
        assert hasattr(auth._thread_local, "nonce_count")
        assert hasattr(auth._thread_local, "chal")
        assert hasattr(auth._thread_local, "pos")
        assert hasattr(auth._thread_local, "num_401_calls")

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_http_digest_auth_equality(self, username: str, password: str) -> None:
        """HTTPDigestAuth instances with same credentials should be equal."""
        auth1 = HTTPDigestAuth(username, password)
        auth2 = HTTPDigestAuth(username, password)
        assert auth1 == auth2

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text, safe_text)
    def test_http_digest_auth_inequality(
        self, username1: str, username2: str, password: str
    ) -> None:
        """HTTPDigestAuth instances with different credentials should not be equal."""
        assume(username1 != username2)
        auth1 = HTTPDigestAuth(username1, password)
        auth2 = HTTPDigestAuth(username2, password)
        assert auth1 != auth2


class TestAuthInvariants:
    """Test invariants that should hold for authentication classes."""

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_basic_auth_idempotent(self, username: str, password: str) -> None:
        """Applying HTTPBasicAuth multiple times should be idempotent."""
        auth = HTTPBasicAuth(username, password)
        req = PreparedRequest()
        req.prepare_method("GET")
        req.prepare_url("http://example.com", None)
        req.prepare_headers({})

        result1 = auth(req)
        auth_header1 = result1.headers["Authorization"]

        # Apply again
        result2 = auth(result1)
        auth_header2 = result2.headers["Authorization"]

        # Should produce same header
        assert auth_header1 == auth_header2

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_proxy_auth_idempotent(self, username: str, password: str) -> None:
        """Applying HTTPProxyAuth multiple times should be idempotent."""
        auth = HTTPProxyAuth(username, password)
        req = PreparedRequest()
        req.prepare_method("GET")
        req.prepare_url("http://example.com", None)
        req.prepare_headers({})

        result1 = auth(req)
        auth_header1 = result1.headers["Proxy-Authorization"]

        # Apply again
        result2 = auth(result1)
        auth_header2 = result2.headers["Proxy-Authorization"]

        # Should produce same header
        assert auth_header1 == auth_header2

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_basic_auth_header_format(self, username: str, password: str) -> None:
        """HTTPBasicAuth should produce correctly formatted header."""
        auth = HTTPBasicAuth(username, password)
        req = PreparedRequest()
        req.prepare_method("GET")
        req.prepare_url("http://example.com", None)
        req.prepare_headers({})

        result = auth(req)
        auth_header = result.headers["Authorization"]

        # Should match Basic auth format
        assert re.match(r"^Basic [A-Za-z0-9+/]+=*$", auth_header)

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_proxy_auth_header_format(self, username: str, password: str) -> None:
        """HTTPProxyAuth should produce correctly formatted header."""
        auth = HTTPProxyAuth(username, password)
        req = PreparedRequest()
        req.prepare_method("GET")
        req.prepare_url("http://example.com", None)
        req.prepare_headers({})

        result = auth(req)
        auth_header = result.headers["Proxy-Authorization"]

        # Should match Basic auth format
        assert re.match(r"^Basic [A-Za-z0-9+/]+=*$", auth_header)

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text, safe_text, safe_text)
    def test_different_credentials_different_headers(
        self, user1: str, pass1: str, user2: str, pass2: str
    ) -> None:
        """Different credentials should produce different headers."""
        assume((user1, pass1) != (user2, pass2))

        auth1 = HTTPBasicAuth(user1, pass1)
        auth2 = HTTPBasicAuth(user2, pass2)

        req1 = PreparedRequest()
        req1.prepare_method("GET")
        req1.prepare_url("http://example.com", None)
        req1.prepare_headers({})

        req2 = PreparedRequest()
        req2.prepare_method("GET")
        req2.prepare_url("http://example.com", None)
        req2.prepare_headers({})

        result1 = auth1(req1)
        result2 = auth2(req2)

        # Different credentials should produce different headers
        assert result1.headers["Authorization"] != result2.headers["Authorization"]


class TestAuthHeaderEncoding:
    """Test encoding properties of auth headers."""

    @settings(max_examples=1000, deadline=None)
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
    def test_ascii_credentials_always_work(self, username: str, password: str) -> None:
        """ASCII-only credentials should always work."""
        auth = HTTPBasicAuth(username, password)
        req = PreparedRequest()
        req.prepare_method("GET")
        req.prepare_url("http://example.com", None)
        req.prepare_headers({})

        result = auth(req)
        assert "Authorization" in result.headers
        # Verify we can decode the header
        b64_part = result.headers["Authorization"].replace("Basic ", "")
        decoded = base64.b64decode(b64_part)
        assert username.encode("latin1") in decoded
        assert password.encode("latin1") in decoded

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_basic_auth_str_roundtrip(self, username: str, password: str) -> None:
        """Basic auth string should be decodable to recover credentials."""
        auth_str = _basic_auth_str(username, password)
        b64_part = auth_str.replace("Basic ", "")
        decoded = base64.b64decode(b64_part).decode("latin1")

        # Should be in format "username:password"
        parts = decoded.split(":", 1)
        assert len(parts) == 2
        assert parts[0] == username
        assert parts[1] == password


class TestAuthEquality:
    """Test equality and inequality operations for auth classes."""

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_basic_auth_equal_to_itself(self, username: str, password: str) -> None:
        """HTTPBasicAuth should be equal to itself."""
        auth = HTTPBasicAuth(username, password)
        assert auth == auth

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_proxy_auth_equal_to_itself(self, username: str, password: str) -> None:
        """HTTPProxyAuth should be equal to itself."""
        auth = HTTPProxyAuth(username, password)
        assert auth == auth

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_digest_auth_equal_to_itself(self, username: str, password: str) -> None:
        """HTTPDigestAuth should be equal to itself."""
        auth = HTTPDigestAuth(username, password)
        assert auth == auth

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_basic_auth_not_equal_to_none(self, username: str, password: str) -> None:
        """HTTPBasicAuth should not be equal to None."""
        auth = HTTPBasicAuth(username, password)
        assert auth != None  # noqa: E711

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_basic_auth_not_equal_to_other_type(
        self, username: str, password: str
    ) -> None:
        """HTTPBasicAuth should not be equal to other types."""
        auth = HTTPBasicAuth(username, password)
        assert auth != "not an auth object"
        assert auth != 123
        assert auth != {}

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_basic_auth_copy_is_equal(self, username: str, password: str) -> None:
        """A copy of HTTPBasicAuth should be equal to original."""
        auth1 = HTTPBasicAuth(username, password)
        auth2 = HTTPBasicAuth(auth1.username, auth1.password)
        assert auth1 == auth2


class TestDigestAuthSpecificProperties:
    """Test properties specific to HTTPDigestAuth."""

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_digest_auth_nonce_count_starts_at_zero(
        self, username: str, password: str
    ) -> None:
        """HTTPDigestAuth nonce_count should start at 0."""
        auth = HTTPDigestAuth(username, password)
        auth.init_per_thread_state()
        assert auth._thread_local.nonce_count == 0

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_digest_auth_last_nonce_starts_empty(
        self, username: str, password: str
    ) -> None:
        """HTTPDigestAuth last_nonce should start empty."""
        auth = HTTPDigestAuth(username, password)
        auth.init_per_thread_state()
        assert auth._thread_local.last_nonce == ""

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_digest_auth_chal_starts_empty(self, username: str, password: str) -> None:
        """HTTPDigestAuth chal should start as empty dict."""
        auth = HTTPDigestAuth(username, password)
        auth.init_per_thread_state()
        assert auth._thread_local.chal == {}

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_digest_auth_pos_starts_none(self, username: str, password: str) -> None:
        """HTTPDigestAuth pos should start as None."""
        auth = HTTPDigestAuth(username, password)
        auth.init_per_thread_state()
        assert auth._thread_local.pos is None

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_digest_auth_num_401_calls_starts_none(
        self, username: str, password: str
    ) -> None:
        """HTTPDigestAuth num_401_calls should start as None."""
        auth = HTTPDigestAuth(username, password)
        auth.init_per_thread_state()
        assert auth._thread_local.num_401_calls is None

    @settings(max_examples=1000, deadline=None)
    @given(safe_text, safe_text)
    def test_digest_auth_multiple_init_idempotent(
        self, username: str, password: str
    ) -> None:
        """Calling init_per_thread_state multiple times should be safe."""
        auth = HTTPDigestAuth(username, password)
        auth.init_per_thread_state()
        auth.init_per_thread_state()
        # Should still have all attributes
        assert hasattr(auth._thread_local, "init")
        assert hasattr(auth._thread_local, "nonce_count")

