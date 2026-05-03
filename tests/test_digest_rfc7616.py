"""Tests for RFC 7616 HTTPDigestAuth non-Latin credential handling."""

import pytest

from requests.auth import HTTPDigestAuth


class TestDigestAuthRFC7616:
    """Test RFC 7616 extensions for HTTP Digest Authentication.

    RFC 7616 adds support for:
    - username* parameter with RFC 5987 encoding for non-Latin-1 usernames
    - userhash parameter to hash the username for privacy
    - charset parameter to indicate UTF-8 support
    """

    def _setup_auth(self, username, password, chal_overrides=None):
        """Create an HTTPDigestAuth instance with a pre-populated challenge."""
        auth = HTTPDigestAuth(username, password)
        auth.init_per_thread_state()
        chal = {
            "realm": "test@example.com",
            "nonce": "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            "qop": "auth",
            "algorithm": "MD5",
        }
        if chal_overrides:
            chal.update(chal_overrides)
        auth._thread_local.chal = chal
        return auth

    def test_latin1_username_uses_standard_parameter(self):
        """Latin-1 encodable usernames should use the standard username parameter."""
        auth = self._setup_auth("user", "pass")
        header = auth.build_digest_header("GET", "http://example.com/")
        assert header is not None
        assert 'username="user"' in header
        assert "username*=" not in header

    def test_non_latin1_username_uses_username_star(self):
        """Non-Latin-1 usernames should use the username* parameter (RFC 5987)."""
        auth = self._setup_auth("Ondřej", "heslíčko")
        header = auth.build_digest_header("GET", "http://example.com/")
        assert header is not None
        assert "username*=UTF-8''" in header
        assert 'username="' not in header

    def test_cyrillic_username_uses_username_star(self):
        """Cyrillic usernames must use username* since they're not Latin-1."""
        auth = self._setup_auth("Сергей", "пароль")
        header = auth.build_digest_header("GET", "http://example.com/")
        assert header is not None
        assert "username*=UTF-8''" in header
        assert 'username="' not in header

    def test_latin1_extended_username_uses_standard(self):
        """Characters like ü, é, ñ ARE Latin-1 and should use standard username."""
        auth = self._setup_auth("José", "contraseña")
        header = auth.build_digest_header("GET", "http://example.com/")
        assert header is not None
        assert 'username="José"' in header
        assert "username*=" not in header

    def test_userhash_hashes_username(self):
        """When userhash=true, the username should be hashed (RFC 7616 §3.4.4)."""
        auth = self._setup_auth("user", "pass", {"userhash": "true"})
        header = auth.build_digest_header("GET", "http://example.com/")
        assert header is not None
        # The username in the header should NOT be "user" in plain text
        assert 'username="user"' not in header
        assert "userhash=true" in header
        # It should be a hex hash instead
        assert 'username="' in header

    def test_userhash_false_uses_plain_username(self):
        """When userhash=false (default), username should appear in plain text."""
        auth = self._setup_auth("user", "pass", {"userhash": "false"})
        header = auth.build_digest_header("GET", "http://example.com/")
        assert header is not None
        assert 'username="user"' in header
        assert "userhash=true" not in header

    def test_charset_utf8_included_when_advertised(self):
        """charset=UTF-8 should be echoed when the server advertises it."""
        auth = self._setup_auth("user", "pass", {"charset": "UTF-8"})
        header = auth.build_digest_header("GET", "http://example.com/")
        assert header is not None
        assert 'charset="UTF-8"' in header

    def test_charset_not_included_when_not_advertised(self):
        """charset should not appear when server doesn't advertise it."""
        auth = self._setup_auth("user", "pass")
        header = auth.build_digest_header("GET", "http://example.com/")
        assert header is not None
        assert "charset" not in header

    def test_is_latin1_encodable(self):
        """Test the Latin-1 encoding check helper."""
        assert HTTPDigestAuth._is_latin1_encodable("hello") is True
        assert HTTPDigestAuth._is_latin1_encodable("José") is True
        assert HTTPDigestAuth._is_latin1_encodable("über") is True
        assert HTTPDigestAuth._is_latin1_encodable("Ondřej") is False
        assert HTTPDigestAuth._is_latin1_encodable("Сергей") is False
        assert HTTPDigestAuth._is_latin1_encodable("日本語") is False

    def test_encode_rfc5987(self):
        """Test RFC 5987 encoding of values."""
        # ASCII string should pass through mostly unchanged
        result = HTTPDigestAuth._encode_rfc5987("hello")
        assert result == "UTF-8''hello"

        # Non-ASCII should be percent-encoded
        result = HTTPDigestAuth._encode_rfc5987("Ondřej")
        assert result.startswith("UTF-8''Ond")
        assert "%C5%99" in result  # ř encoded as UTF-8

    def test_non_latin1_username_generates_valid_response(self):
        """Ensure the response digest is still computed correctly with non-Latin usernames."""
        auth = self._setup_auth("Ondřej", "heslíčko")
        header = auth.build_digest_header("GET", "http://example.com/dir/index.html")
        assert header is not None
        assert header.startswith("Digest ")
        # Should contain all required digest fields
        assert "realm=" in header
        assert "nonce=" in header
        assert "uri=" in header
        assert "response=" in header
        assert "qop=" in header
        assert "nc=" in header
        assert "cnonce=" in header
