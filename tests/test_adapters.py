import pytest

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
        "url, has_zone_id",
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
        ],
    )
    def test_has_ipv6_zone_id(self, url: str, has_zone_id: bool) -> None:
        """Test detection of IPv6 zone identifiers in URLs."""
        assert _has_ipv6_zone_id(url) == has_zone_id


class TestIPv6ZoneIDParsing:
    """Test that IPv6 addresses with zone identifiers are parsed correctly."""

    @pytest.mark.parametrize(
        "url, expected_host, expected_port, expected_scheme",
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

        # This should not raise an error
        host_params, pool_kwargs = adapter.build_connection_pool_key_attributes(
            req, verify=False, cert=None
        )

        assert host_params["host"] == "fe80::1%eth0"
        assert host_params["scheme"] == "https"
        assert "cert_reqs" in pool_kwargs
