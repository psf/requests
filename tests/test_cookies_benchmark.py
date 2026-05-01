"""Performance benchmarks for cookies module."""

from typing import Any

import pytest

from requests.cookies import RequestsCookieJar, create_cookie


def create_jar_with_cookies(
    num_cookies: int, num_domains: int, second_domain_position: int | None = None
) -> RequestsCookieJar:
    """Create a cookie jar with specified number of cookies and domains.

    :param num_cookies: Total number of cookies to create
    :param num_domains: Number of unique domains to distribute cookies across
    :param second_domain_position: Position where second domain should appear (0-indexed)
                                   If None, domains are distributed evenly
    :return: RequestsCookieJar with cookies
    """
    jar = RequestsCookieJar()

    if second_domain_position is not None:
        # Special case: put all cookies in domain1 except one at specific position
        for i in range(num_cookies):
            if i == second_domain_position:
                domain = "domain2.com"
            else:
                domain = "domain1.com"
            cookie = create_cookie(
                name=f"cookie_{i}",
                value=f"value_{i}",
                domain=domain,
                path="/",
            )
            jar.set_cookie(cookie)
    else:
        # Distribute cookies evenly across domains
        for i in range(num_cookies):
            domain_idx = i % num_domains
            cookie = create_cookie(
                name=f"cookie_{i}",
                value=f"value_{i}",
                domain=f"domain{domain_idx}.com",
                path="/",
            )
            jar.set_cookie(cookie)

    return jar


class TestMultipleDomainsPerformance:
    """Benchmarks for multiple_domains() method."""

    def test_early_return_best_case(self, benchmark: Any) -> None:
        """Benchmark when second domain appears at position 1 (best case).

        This tests the short-circuit optimization - should return immediately
        after checking only 2 cookies.
        """
        jar = create_jar_with_cookies(
            num_cookies=500, num_domains=1, second_domain_position=1
        )
        result = benchmark(jar.multiple_domains)
        assert result is True

    def test_early_return_position_10(self, benchmark: Any) -> None:
        """Benchmark when second domain appears at position 10.

        Should return after checking only 11 cookies out of 500.
        """
        jar = create_jar_with_cookies(
            num_cookies=500, num_domains=1, second_domain_position=10
        )
        result = benchmark(jar.multiple_domains)
        assert result is True

    def test_late_return_worst_case_multiple_domains(self, benchmark: Any) -> None:
        """Benchmark when second domain appears at the end (worst case for True).

        This is the worst case for returning True - must iterate through
        almost all cookies before finding the second domain.
        """
        jar = create_jar_with_cookies(
            num_cookies=500, num_domains=1, second_domain_position=499
        )
        result = benchmark(jar.multiple_domains)
        assert result is True

    def test_single_domain_must_iterate_all(self, benchmark: Any) -> None:
        """Benchmark when all cookies have same domain (no early return possible).

        This is the worst case for returning False - must check every cookie
        to confirm there's only one domain.
        """
        jar = create_jar_with_cookies(num_cookies=500, num_domains=1)
        result = benchmark(jar.multiple_domains)
        assert result is False

    def test_many_domains_distributed(self, benchmark: Any) -> None:
        """Benchmark with many domains distributed throughout.

        Should return True very early (after checking first 2 cookies with
        different domains).
        """
        jar = create_jar_with_cookies(num_cookies=500, num_domains=10)
        result = benchmark(jar.multiple_domains)
        assert result is True

    def test_realistic_scenario_100_cookies(self, benchmark: Any) -> None:
        """Benchmark realistic scenario with 100 cookies across 3 domains.

        Simulates a typical browser session with cookies from multiple sites.
        """
        jar = create_jar_with_cookies(num_cookies=100, num_domains=3)
        result = benchmark(jar.multiple_domains)
        assert result is True

    def test_realistic_scenario_200_cookies_single_domain(self, benchmark: Any) -> None:
        """Benchmark realistic scenario with 200 cookies from single domain.

        Simulates a cookie-heavy single-page application.
        """
        jar = create_jar_with_cookies(num_cookies=200, num_domains=1)
        result = benchmark(jar.multiple_domains)
        assert result is False

    def test_empty_jar(self, benchmark: Any) -> None:
        """Benchmark with empty cookie jar."""
        jar = RequestsCookieJar()
        result = benchmark(jar.multiple_domains)
        assert result is False

    def test_very_small_jar_two_domains(self, benchmark: Any) -> None:
        """Benchmark with just 2 cookies from different domains."""
        jar = create_jar_with_cookies(num_cookies=2, num_domains=2)
        result = benchmark(jar.multiple_domains)
        assert result is True

    def test_very_small_jar_single_domain(self, benchmark: Any) -> None:
        """Benchmark with just 2 cookies from same domain."""
        jar = create_jar_with_cookies(num_cookies=2, num_domains=1)
        result = benchmark(jar.multiple_domains)
        assert result is False

