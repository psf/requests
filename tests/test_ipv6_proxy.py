import pytest
from requests.utils import should_bypass_proxies

class TestIPv6ProxyBypass:
    @pytest.mark.parametrize(
        "url, no_proxy, expected",
        [
            # Basic IPv6 CIDR match
            ("http://[2001:db8::1]", "2001:db8::/32", True),
            # IPv6 CIDR mismatch
            ("http://[2001:db8::1]", "2001:db9::/32", False),
            # Compressed vs Uncompressed
            ("http://[2001:0db8:0000:0000:0000:0000:0000:0001]", "2001:db8::/32", True),
            # Multiple no_proxy items
            ("http://[2001:db8::1]", "example.com, 2001:db8::/32", True),
            # IPv4 should still work
            ("http://192.168.1.5", "192.168.1.0/24", True),
        ]
    )
    def test_ipv6_cidr_bypass(self, url, no_proxy, expected, monkeypatch):
        monkeypatch.setenv("no_proxy", no_proxy)
        monkeypatch.setenv("NO_PROXY", no_proxy)
        assert should_bypass_proxies(url, no_proxy=None) == expected
