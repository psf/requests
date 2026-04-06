"""Tests for Digest Auth URI handling (issue #6990)."""

import requests
from requests.auth import HTTPDigestAuth


def test_digest_auth_uri_includes_semicolon_params():
    """Digest auth URI must include semicolon path parameters (issue #6990)."""
    auth = HTTPDigestAuth("user", "pass")
    auth._thread_local.chal = {
        "realm": "testrealm",
        "nonce": "testnonce",
        "qop": "auth",
    }
    auth._thread_local.last_nonce = ""
    auth._thread_local.nonce_count = 0

    url = "http://example.com/path;jsessionid=abc123?q=1"
    header = auth.build_digest_header("GET", url)

    assert 'uri="/path;jsessionid=abc123?q=1"' in header


def test_digest_auth_uri_without_semicolon_params():
    """Digest auth URI is unchanged for URLs without semicolon path params."""
    auth = HTTPDigestAuth("user", "pass")
    auth._thread_local.chal = {
        "realm": "testrealm",
        "nonce": "testnonce",
        "qop": "auth",
    }
    auth._thread_local.last_nonce = ""
    auth._thread_local.nonce_count = 0

    url = "http://example.com/path?q=1"
    header = auth.build_digest_header("GET", url)

    assert 'uri="/path?q=1"' in header
