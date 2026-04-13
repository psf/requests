import sys
from unittest.mock import MagicMock

import pytest
from urllib3 import HTTPResponse

import requests
import requests.adapters
from requests.adapters import _has_ipv6_zone_id


def test_request_url_trims_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6643."""
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "/v:h" == a.request_url(p, {})


class TestIPv6ZoneIDDetection:
    """Test the helper function that detects IPv6 zone identifiers."""

    @pytest.mark.parametrize(
        ("url", "has_zone_id"),
        [
            # URLs with IPv6 zone identifiers
            ("http://[fe80::1%eth0]:8080/", True),
            ("http://[fe80::5054:ff:fe5a:fc0%enp1s0]:80/", True),
            ("http://[fe80::1%25eth0]:8080/", True),  # URL-encoded %
            ("https://[fe80::1%lo]/path", True),
            ("http://[2001:db8::1%eth0]:443/", True),
            # URLs without zone identifiers
            ("http://[fe80::1]:8080/", False),
            ("http://[1200:0000:ab00:1234:0000:2552:7777:1313]:12345/", False),
            ("http://[::1]/", False),
            ("http://example.com:8080/", False),
            ("http://192.168.1.1:8080/", False),
            ("https://google.com/", False),
            ("http://localhost/", False),
            ("http://example.com/foo%20bar", False),  # % in path, not zone ID
            ("http://[::1]/path%20with%20percent", False),  # % in path, not in host
            # False-positive guard: percent-encoded chars inside brackets are NOT zone IDs
            ("http://[::1%20]/", False),  # %20 = space encoding, not a zone ID
            ("http://[::1%2F]/", False),  # %2F = slash encoding, not a zone ID
            ("http://[::1%2B]/", False),  # %2B = plus encoding, not a zone ID
            ("http://[::1%41]/", False),  # %41 = 'A', two hex digits, not a zone ID
            ("http://[fe80::1%20]:8080/", False),  # %20 in host with port
            (
                "http://[::1%25]/",
                False,
            ),  # bare %25 with nothing after it is not a zone ID
            # Edge cases with multiple percent signs
            ("http://[fe80::1%eth0]/path%20test", True),  # Zone ID + path encoding
            (
                "http://[fe80::1%25eth0]/path%20test",
                True,
            ),  # %25 zone ID + path encoding
            ("http://[::1]/query?param=%20value", False),  # % in query, not zone ID
            (
                "http://[::1]:8080/path%20with%20multiple%20percents",
                False,
            ),  # Multiple % in path
            # Additional %25 encoding tests
            ("http://[fe80::1%25lo]:9090/", True),  # %25 with different port
            ("https://[2001:db8::1%25wlan0]:443/path", True),  # HTTPS with %25 zone ID
            # Brackets in path/query must NOT trigger zone-ID detection (Bug 1 guard)
            ("http://example.com/api/[data%25value]", False),  # brackets in path
            (
                "http://[::1]/path/[data%25value]",
                False,
            ),  # brackets in path after real host
            ("http://example.com/search?q=[tag%25foo]", False),  # brackets in query
            # Hex-letter percent-encoded bytes inside host brackets are NOT zone IDs (Bug 2 guard)
            ("http://[::1%AB]/", False),  # %AB = valid hex byte, not a zone ID
            (
                "http://[::1%aF]/",
                False,
            ),  # %aF = valid hex byte (mixed case), not a zone ID
            ("http://[::1%CD]/", False),  # %CD = valid hex byte, not a zone ID
            ("http://[::1%EF]/", False),  # %EF = valid hex byte, not a zone ID
            ("http://[fe80::1%AB]:8080/", False),  # %AB with port, still not a zone ID
            # Zone IDs whose names contain percent-encoded characters (e.g. spaces)
            ("http://[fe80::1%25Ethernet%203]:8080/", True),  # zone ID "Ethernet 3"
            ("http://[fe80::1%25eth%200]:8080/", True),  # zone ID "eth 0"
            # Numeric zone IDs encoded via %25 (RFC 6874) - regression for %2550 handling
            (
                "http://[fe80::1%2550]:8080/",
                True,
            ),  # zone ID "50" (numeric), %2550 = %25 + 50
            # Raw numeric zone IDs (Linux zone indices)
            ("http://[fe80::1%1]:8080/", True),  # single-digit zone index
            ("http://[fe80::1%3]:8080/", True),  # single-digit zone index
            ("http://[fe80::1%9]:8080/", True),  # single-digit zone index
        ],
    )
    def test_has_ipv6_zone_id(self, url: str, has_zone_id: bool) -> None:
        """Test detection of IPv6 zone identifiers in URLs."""
        assert _has_ipv6_zone_id(url) == has_zone_id


class TestIPv6ZoneIDParsing:
    """Test that IPv6 addresses with zone identifiers are parsed correctly."""

    @pytest.mark.parametrize(
        ("url", "expected_host", "expected_port", "expected_scheme"),
        [
            # IPv6 with zone identifiers
            (
                "http://[fe80::1%eth0]:8080/path",
                "fe80::1%eth0",
                8080,
                "http",
            ),
            (
                "http://[fe80::5054:ff:fe5a:fc0%enp1s0]:80/",
                "fe80::5054:ff:fe5a:fc0%enp1s0",
                80,
                "http",
            ),
            (
                "http://[fe80::1%25eth0]:8080/",
                "fe80::1%eth0",  # %25 is decoded to % by parse_url
                8080,
                "http",
            ),
            (
                "https://[fe80::1%lo]/",
                "fe80::1%lo",
                None,
                "https",
            ),
            # Regular IPv6 (no zone ID) - should still work
            (
                "http://[fe80::1]:8080/",
                "fe80::1",
                8080,
                "http",
            ),
            (
                "http://[1200:0000:ab00:1234:0000:2552:7777:1313]:12345/",
                "1200:0000:ab00:1234:0000:2552:7777:1313",
                12345,
                "http",
            ),
            (
                "http://[::1]/",
                "::1",
                None,
                "http",
            ),
            # Regular hostnames and IPv4
            (
                "http://example.com:8080/",
                "example.com",
                8080,
                "http",
            ),
            (
                "http://192.168.1.1:9000/",
                "192.168.1.1",
                9000,
                "http",
            ),
            (
                "https://google.com/",
                "google.com",
                None,
                "https",
            ),
            # Edge cases: %25 encoding variations
            (
                "http://[fe80::1%25lo]:9090/",
                "fe80::1%lo",  # %25 decoded to %
                9090,
                "http",
            ),
            (
                "https://[2001:db8::1%25wlan0]:443/path",
                "2001:db8::1%wlan0",
                443,
                "https",
            ),
            # Edge cases: Zone ID with path encoding
            (
                "http://[fe80::1%eth0]/path%20test",
                "fe80::1%eth0",
                None,
                "http",
            ),
            (
                "http://[fe80::1%25eth0]/path%20test",
                "fe80::1%eth0",  # %25 in zone ID decoded, %20 in path preserved
                None,
                "http",
            ),
            # Numeric zone ID via %2550 (regression: models.py must re-encode %50 -> %2550
            # so Python 3.14's urlparse does not decode %50 to 'P' and reject the address)
            (
                "http://[fe80::1%2550]:8080/",
                "fe80::1%50",  # %25 decoded to % by parse_url, zone name is "50"
                8080,
                "http",
            ),
        ],
    )
    def test_ipv6_zone_id_url_parsing(
        self,
        url: str,
        expected_host: str,
        expected_port: "int | None",
        expected_scheme: str,
    ) -> None:
        """Test that URLs with IPv6 zone IDs are parsed correctly."""
        adapter = requests.adapters.HTTPAdapter()
        prepared_request = requests.Request("GET", url).prepare()

        # Test that build_connection_pool_key_attributes works correctly
        host_params, pool_kwargs = adapter.build_connection_pool_key_attributes(
            prepared_request, verify=True
        )

        assert host_params["scheme"] == expected_scheme
        assert host_params["host"] == expected_host
        assert host_params["port"] == expected_port
        # Verify SSL context is set up correctly
        assert "cert_reqs" in pool_kwargs


class TestIPv6ZoneIDRequests:
    """Integration tests for making requests to IPv6 addresses with zone IDs."""

    def test_ipv6_zone_id_connection_pool_key(self) -> None:
        """Test that connection pool keys are properly generated for IPv6 zone IDs."""
        adapter = requests.adapters.HTTPAdapter()

        # Test with IPv6 zone ID
        req1 = requests.Request("GET", "http://[fe80::1%eth0]:8080/").prepare()
        host_params1, _ = adapter.build_connection_pool_key_attributes(
            req1, verify=False
        )

        # Test with different zone ID (should be different pool key)
        req2 = requests.Request("GET", "http://[fe80::1%eth1]:8080/").prepare()
        host_params2, _ = adapter.build_connection_pool_key_attributes(
            req2, verify=False
        )

        # Should have different hosts due to different zone IDs
        assert host_params1["host"] != host_params2["host"]
        assert host_params1["host"] == "fe80::1%eth0"
        assert host_params2["host"] == "fe80::1%eth1"

    def test_ipv6_zone_id_with_client_cert(self) -> None:
        """Test that client certificates work with IPv6 zone IDs."""
        adapter = requests.adapters.HTTPAdapter()
        req = requests.Request("GET", "https://[fe80::1%eth0]:8443/").prepare()

        cert = ("/path/to/client.pem", "/path/to/client.key")
        host_params, pool_kwargs = adapter.build_connection_pool_key_attributes(
            req, verify=False, cert=cert
        )

        assert host_params["host"] == "fe80::1%eth0"
        assert host_params["scheme"] == "https"
        assert "cert_reqs" in pool_kwargs
        assert pool_kwargs["cert_file"] == "/path/to/client.pem"
        assert pool_kwargs["key_file"] == "/path/to/client.key"

    def test_ipv6_zone_id_full_request_flow_with_mocking(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Integration test: Full request flow from PreparedRequest to connection pool."""
        # Create adapter and prepare request with %25-encoded zone ID
        adapter = requests.adapters.HTTPAdapter()
        url = "http://[fe80::1%25eth0]:8080/api/test"
        req = requests.Request("GET", url).prepare()

        # Verify URL is properly canonicalized after prepare
        assert "%25" in req.url  # Should maintain %25 encoding

        # Mock the connection pool's urlopen method
        mock_response = HTTPResponse(
            body=b"test response",
            headers={"Content-Type": "application/json"},
            status=200,
            preload_content=False,
        )

        # Mock connection_from_host to capture the host parameter
        captured_host = None

        def mock_connection_from_host(*args: object, **kwargs: object) -> MagicMock:
            nonlocal captured_host
            # Capture the host from kwargs if present, otherwise from args
            if "host" in kwargs:
                captured_host = kwargs["host"]
            mock_conn = MagicMock()
            mock_conn.urlopen.return_value = mock_response
            return mock_conn

        monkeypatch.setattr(
            adapter.poolmanager,
            "connection_from_host",
            mock_connection_from_host,
        )

        response = adapter.send(req, verify=False)
        assert response.status_code == 200
        assert captured_host == "fe80::1%eth0"

    def test_ipv6_zone_id_different_encodings_create_correct_pools(self) -> None:
        """Test that %25 and raw % encodings both produce the same pool key."""
        adapter = requests.adapters.HTTPAdapter()

        # RFC 6874 compliant %25-encoded zone ID
        req1 = requests.Request("GET", "http://[fe80::1%25eth0]:8080/").prepare()
        host_params1, _ = adapter.build_connection_pool_key_attributes(
            req1, verify=False
        )

        # Raw (literal) % zone ID form
        req2 = requests.Request("GET", "http://[fe80::1%eth0]:8080/").prepare()
        host_params2, _ = adapter.build_connection_pool_key_attributes(
            req2, verify=False
        )

        # Both encodings must resolve to the same internal host representation
        assert host_params1["host"] == "fe80::1%eth0"
        assert host_params1["port"] == 8080
        assert host_params1["scheme"] == "http"
        assert host_params2["host"] == host_params1["host"]
        assert host_params2["port"] == host_params1["port"]
        assert host_params2["scheme"] == host_params1["scheme"]

    def test_ipv6_zone_id_preserved_through_url_preparation(self) -> None:
        """Test that zone IDs are preserved through the entire URL preparation flow."""
        # Start with a URL that has %25-encoded zone ID
        original_url = "http://[fe80::1%25eth0]:8080/path?query=value"

        # Prepare the request (this goes through prepare_url in models.py)
        req = requests.Request("GET", original_url).prepare()

        # The prepared URL should maintain %25 encoding (canonical form)
        assert "%25" in req.url
        assert "fe80::1" in req.url
        assert "eth0" in req.url

        # Now test that adapter can parse this correctly
        adapter = requests.adapters.HTTPAdapter()
        host_params, _ = adapter.build_connection_pool_key_attributes(req, verify=False)

        # The host should have single % (decoded for connection)
        assert host_params["host"] == "fe80::1%eth0"

    def test_ipv6_zone_id_with_percent_encoded_name(self) -> None:
        """Zone IDs whose names contain %XX-encoded characters (e.g. spaces) behave
        differently depending on the Python version.

        Python 3.14 added _check_bracketed_netloc to urlparse, which calls
        ipaddress.ip_address() on the bracketed host.  Python's ipaddress splits
        on the first literal % to extract the scope ID, so a URL like
        http://[fe80::1%25Ethernet%203]:8080/ yields scope "25Ethernet%203" which
        contains a bare % and is rejected.

        On Python < 3.14 urlparse does not perform this validation, so the full
        pipeline (prepare -> adapter parsing) works correctly.
        """
        original_url = "http://[fe80::1%25Ethernet%203]:8080/path"

        if sys.version_info >= (3, 14):
            # urlparse now validates IPv6 scope IDs; % inside the scope is rejected
            with pytest.raises((ValueError, requests.exceptions.InvalidURL)):
                requests.Request("GET", original_url).prepare()
        else:
            req = requests.Request("GET", original_url).prepare()

            # models.py re-encodes the zone delimiter so %25 is preserved
            assert "%25" in req.url
            assert "Ethernet" in req.url

            adapter = requests.adapters.HTTPAdapter()
            host_params, _ = adapter.build_connection_pool_key_attributes(
                req, verify=False
            )

            # parse_url decodes %25 -> % when returning the host for the connection
            assert host_params["host"] == "fe80::1%Ethernet%203"
            assert host_params["port"] == 8080
            assert host_params["scheme"] == "http"

    @pytest.mark.parametrize(
        ("url", "expected_path"),
        [
            ("http://[fe80::1%25eth0]:8080/api/test", "/api/test"),
            ("http://[fe80::1%25eth0]:8080/", "/"),
            ("http://[fe80::1%25eth0]/path?q=1", "/path?q=1"),
            ("http://[fe80::1%25lo]:9090/a/b/c", "/a/b/c"),
        ],
    )
    def test_ipv6_zone_id_request_url(self, url: str, expected_path: str) -> None:
        """Test that request_url() extracts the correct path for zone ID URLs."""
        adapter = requests.adapters.HTTPAdapter()
        req = requests.Request("GET", url).prepare()
        assert adapter.request_url(req, {}) == expected_path

    def test_ipv6_zone_id_proxy_connection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that zone ID URLs work through the proxy path in
        get_connection_with_tls_context."""
        adapter = requests.adapters.HTTPAdapter()
        url = "http://[fe80::1%25eth0]:8080/api/test"
        req = requests.Request("GET", url).prepare()

        captured_host_params: dict = {}

        def mock_proxy_connection_from_host(
            *args: object, **kwargs: object
        ) -> MagicMock:
            captured_host_params["host"] = kwargs.get("host")
            captured_host_params["scheme"] = kwargs.get("scheme")
            captured_host_params["port"] = kwargs.get("port")
            mock_conn = MagicMock()
            return mock_conn

        mock_proxy_manager = MagicMock()
        mock_proxy_manager.connection_from_host = mock_proxy_connection_from_host
        monkeypatch.setattr(
            adapter, "proxy_manager_for", lambda proxy, **kw: mock_proxy_manager
        )

        adapter.get_connection_with_tls_context(
            req, verify=False, proxies={"http": "http://proxy.example.com:3128"}
        )

        assert captured_host_params["host"] == "fe80::1%eth0"
        assert captured_host_params["scheme"] == "http"
        assert captured_host_params["port"] == 8080
