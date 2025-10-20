"""
Hypothesis-based property tests for requests.cookies module.

These tests use property-based testing to verify the invariants and properties
of cookie handling classes and functions.
"""

import http.cookiejar as cookielib
from http.cookies import Morsel

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from requests.cookies import (
    RequestsCookieJar,
    cookiejar_from_dict,
    create_cookie,
    merge_cookies,
)


# Strategies for cookie names and values
cookie_names = st.text(
    alphabet=st.characters(
        min_codepoint=ord("a"), max_codepoint=ord("z")
    ),
    min_size=1,
    max_size=30,
)
# Cookie values: empty strings have special handling, so use non-empty values
cookie_values = st.text(
    alphabet=st.characters(blacklist_characters='"'),
    min_size=1,
    max_size=100,
)


class TestRequestsCookieJarProperties:
    """Property-based tests for RequestsCookieJar class."""

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_from_dict(self, cookies: dict) -> None:
        """cookiejar_from_dict should create RequestsCookieJar from dict."""
        jar = cookiejar_from_dict(cookies)
        assert isinstance(jar, RequestsCookieJar)
        assert len(jar) == len(cookies)

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_preserves_values(self, cookies: dict) -> None:
        """RequestsCookieJar should preserve cookie values."""
        jar = cookiejar_from_dict(cookies)
        for name, value in cookies.items():
            assert jar.get(name) == value

    @given(cookie_names, cookie_values)
    def test_cookiejar_set_get(self, name: str, value: str) -> None:
        """Setting and getting cookies should work."""
        jar = RequestsCookieJar()
        jar.set(name, value)
        assert jar.get(name) == value

    @given(cookie_names, cookie_values)
    def test_cookiejar_setitem_getitem(self, name: str, value: str) -> None:
        """Dict-style access should work."""
        jar = RequestsCookieJar()
        jar[name] = value
        assert jar[name] == value

    @given(cookie_names, cookie_values)
    def test_cookiejar_contains(self, name: str, value: str) -> None:
        """'in' operator should work for cookies."""
        jar = RequestsCookieJar()
        jar[name] = value
        assert name in jar

    @given(st.dictionaries(cookie_names, cookie_values, min_size=1, max_size=20))
    def test_cookiejar_keys(self, cookies: dict) -> None:
        """keys() should return all cookie names."""
        jar = cookiejar_from_dict(cookies)
        keys = jar.keys()
        assert len(keys) == len(cookies)
        assert all(k in cookies for k in keys)

    @given(st.dictionaries(cookie_names, cookie_values, min_size=1, max_size=20))
    def test_cookiejar_values(self, cookies: dict) -> None:
        """values() should return all cookie values."""
        jar = cookiejar_from_dict(cookies)
        values = jar.values()
        assert len(values) == len(cookies)
        assert all(v in cookies.values() for v in values)

    @given(st.dictionaries(cookie_names, cookie_values, min_size=1, max_size=20))
    def test_cookiejar_items(self, cookies: dict) -> None:
        """items() should return name-value pairs."""
        jar = cookiejar_from_dict(cookies)
        items = jar.items()
        assert len(items) == len(cookies)
        assert all(isinstance(item, tuple) and len(item) == 2 for item in items)

    @given(cookie_names, cookie_values)
    def test_cookiejar_delitem(self, name: str, value: str) -> None:
        """Deleting cookies should work."""
        jar = RequestsCookieJar()
        jar[name] = value
        assert name in jar
        del jar[name]
        assert name not in jar

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_len(self, cookies: dict) -> None:
        """len() should return number of cookies."""
        jar = cookiejar_from_dict(cookies)
        assert len(jar) == len(cookies)

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_iteration(self, cookies: dict) -> None:
        """Iterating over jar should yield cookies."""
        jar = cookiejar_from_dict(cookies)
        count = 0
        for cookie in jar:
            count += 1
            assert hasattr(cookie, "name")
            assert hasattr(cookie, "value")
        assert count == len(cookies)

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_copy(self, cookies: dict) -> None:
        """copy() should create independent copy."""
        jar = cookiejar_from_dict(cookies)
        jar_copy = jar.copy()
        assert jar_copy is not jar
        assert len(jar_copy) == len(jar)
        # Verify values are the same
        for name in cookies:
            assert jar.get(name) == jar_copy.get(name)

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_copy_is_independent(self, cookies: dict) -> None:
        """Modifying copy should not affect original."""
        jar = cookiejar_from_dict(cookies)
        jar_copy = jar.copy()
        jar_copy.set("new_cookie", "new_value")
        assert "new_cookie" not in jar

    @given(
        st.dictionaries(cookie_names, cookie_values, max_size=10),
        st.dictionaries(cookie_names, cookie_values, max_size=10),
    )
    def test_cookiejar_update(self, cookies1: dict, cookies2: dict) -> None:
        """update() should merge cookies."""
        jar = cookiejar_from_dict(cookies1)
        jar.update(cookiejar_from_dict(cookies2))
        # All cookies from both dicts should be present
        for name in cookies2:
            assert name in jar


class TestCreateCookieProperties:
    """Property-based tests for create_cookie function."""

    @given(cookie_names, cookie_values)
    def test_create_cookie_basic(self, name: str, value: str) -> None:
        """create_cookie should create valid cookie."""
        cookie = create_cookie(name, value)
        assert isinstance(cookie, cookielib.Cookie)
        assert cookie.name == name
        assert cookie.value == value

    @given(cookie_names, cookie_values)
    def test_create_cookie_has_required_attributes(self, name: str, value: str) -> None:
        """Created cookie should have all required attributes."""
        cookie = create_cookie(name, value)
        assert hasattr(cookie, "name")
        assert hasattr(cookie, "value")
        assert hasattr(cookie, "domain")
        assert hasattr(cookie, "path")
        assert hasattr(cookie, "secure")
        assert hasattr(cookie, "expires")

    @given(
        cookie_names,
        cookie_values,
        st.text(
            alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
            min_size=1,
            max_size=30,
        ),
    )
    def test_create_cookie_with_domain(self, name: str, value: str, domain: str) -> None:
        """create_cookie should accept domain parameter."""
        cookie = create_cookie(name, value, domain=domain)
        assert cookie.domain == domain

    @given(cookie_names, cookie_values, st.text(min_size=1, max_size=50))
    def test_create_cookie_with_path(self, name: str, value: str, path: str) -> None:
        """create_cookie should accept path parameter."""
        cookie = create_cookie(name, value, path=path)
        assert cookie.path == path

    @given(cookie_names, cookie_values, st.booleans())
    def test_create_cookie_with_secure(self, name: str, value: str, secure: bool) -> None:
        """create_cookie should accept secure parameter."""
        cookie = create_cookie(name, value, secure=secure)
        assert cookie.secure == secure


class TestCookieJarFromDictProperties:
    """Property-based tests for cookiejar_from_dict function."""

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_from_dict_creates_jar(self, cookies: dict) -> None:
        """cookiejar_from_dict should create RequestsCookieJar."""
        jar = cookiejar_from_dict(cookies)
        assert isinstance(jar, RequestsCookieJar)

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_from_dict_preserves_all_cookies(self, cookies: dict) -> None:
        """All cookies from dict should be in jar."""
        jar = cookiejar_from_dict(cookies)
        for name, value in cookies.items():
            assert jar.get(name) == value

    @given(
        st.dictionaries(cookie_names, cookie_values, max_size=10),
        st.dictionaries(cookie_names, cookie_values, max_size=10),
    )
    def test_cookiejar_from_dict_with_existing_jar(
        self, cookies1: dict, cookies2: dict
    ) -> None:
        """cookiejar_from_dict should add to existing jar."""
        jar = cookiejar_from_dict(cookies1)
        result = cookiejar_from_dict(cookies2, cookiejar=jar)
        # Should be the same jar
        assert result is jar
        # Should have cookies from both dicts
        for name in cookies2:
            assert name in result

    @given(
        st.dictionaries(cookie_names, cookie_values, min_size=1, max_size=10),
        st.dictionaries(cookie_names, cookie_values, max_size=10),
    )
    def test_cookiejar_from_dict_overwrite(
        self, cookies1: dict, cookies2: dict
    ) -> None:
        """cookiejar_from_dict with overwrite=True should replace cookies."""
        jar = cookiejar_from_dict(cookies1)
        # Add cookies from dict2 with same names
        result = cookiejar_from_dict(cookies2, cookiejar=jar, overwrite=True)
        # Cookies from dict2 should be present
        for name, value in cookies2.items():
            assert result.get(name) == value


class TestMergeCookiesProperties:
    """Property-based tests for merge_cookies function."""

    @given(
        st.dictionaries(cookie_names, cookie_values, max_size=10),
        st.dictionaries(cookie_names, cookie_values, max_size=10),
    )
    def test_merge_cookies_from_dicts(self, cookies1: dict, cookies2: dict) -> None:
        """merge_cookies should merge two dicts into jar."""
        jar = cookiejar_from_dict(cookies1)
        result = merge_cookies(jar, cookies2)
        # Should return a jar
        assert isinstance(result, cookielib.CookieJar)
        # Should contain cookies from both
        for name in cookies2:
            # Cookie should be in the jar
            found = any(c.name == name for c in result)
            assert found

    @given(
        st.dictionaries(cookie_names, cookie_values, max_size=10),
        st.dictionaries(cookie_names, cookie_values, max_size=10),
    )
    def test_merge_cookies_from_jars(self, cookies1: dict, cookies2: dict) -> None:
        """merge_cookies should merge two jars."""
        jar1 = cookiejar_from_dict(cookies1)
        jar2 = cookiejar_from_dict(cookies2)
        result = merge_cookies(jar1, jar2)
        assert isinstance(result, cookielib.CookieJar)

    def test_merge_cookies_raises_on_non_jar(self) -> None:
        """merge_cookies should raise ValueError if first arg is not a jar."""
        with pytest.raises(ValueError):
            merge_cookies({}, {})


class TestRequestsCookieJarDictInterface:
    """Test dict-like interface of RequestsCookieJar."""

    @given(st.dictionaries(cookie_names, cookie_values, min_size=1, max_size=20))
    def test_cookiejar_dict_conversion(self, cookies: dict) -> None:
        """RequestsCookieJar should be convertible to dict."""
        jar = cookiejar_from_dict(cookies)
        result = dict(jar.items())
        assert isinstance(result, dict)
        # All original cookies should be in result
        for name, value in cookies.items():
            assert result.get(name) == value

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_get_dict(self, cookies: dict) -> None:
        """get_dict() should return plain dict."""
        jar = cookiejar_from_dict(cookies)
        result = jar.get_dict()
        assert isinstance(result, dict)
        assert len(result) == len(cookies)

    @given(cookie_names, cookie_values, cookie_values)
    def test_cookiejar_get_with_default(
        self, name: str, value: str, default: str
    ) -> None:
        """get() should return default for missing cookies."""
        jar = RequestsCookieJar()
        assert jar.get(name, default) == default
        jar.set(name, value)
        assert jar.get(name, default) == value

    @given(
        cookie_names,
        cookie_values,
        st.text(
            alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
            min_size=1,
            max_size=20,
        ),
    )
    def test_cookiejar_get_with_domain(
        self, name: str, value: str, domain: str
    ) -> None:
        """get() should support domain parameter."""
        jar = RequestsCookieJar()
        jar.set(name, value, domain=domain)
        result = jar.get(name, domain=domain)
        assert result == value

    @given(cookie_names, cookie_values, st.text(min_size=1, max_size=20))
    def test_cookiejar_get_with_path(self, name: str, value: str, path: str) -> None:
        """get() should support path parameter."""
        jar = RequestsCookieJar()
        jar.set(name, value, path=path)
        result = jar.get(name, path=path)
        assert result == value


class TestRequestsCookieJarInvariants:
    """Test invariants that should always hold for RequestsCookieJar."""

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_is_cookiejar(self, cookies: dict) -> None:
        """RequestsCookieJar should be a CookieJar."""
        jar = cookiejar_from_dict(cookies)
        assert isinstance(jar, cookielib.CookieJar)

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_len_equals_item_count(self, cookies: dict) -> None:
        """len() should equal number of items."""
        jar = cookiejar_from_dict(cookies)
        assert len(jar) == len(list(jar))

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_keys_values_same_length(self, cookies: dict) -> None:
        """keys() and values() should have same length."""
        jar = cookiejar_from_dict(cookies)
        assert len(jar.keys()) == len(jar.values())

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_items_length_equals_len(self, cookies: dict) -> None:
        """items() length should equal len()."""
        jar = cookiejar_from_dict(cookies)
        assert len(jar.items()) == len(jar)

    @given(cookie_names, cookie_values, cookie_values)
    def test_cookiejar_set_get_roundtrip(
        self, name: str, value1: str, value2: str
    ) -> None:
        """Setting a value and getting it should return the same value."""
        jar = RequestsCookieJar()
        jar.set(name, value1)
        assert jar.get(name) == value1
        # Update value
        jar.set(name, value2)
        assert jar.get(name) == value2

    @given(st.dictionaries(cookie_names, cookie_values, min_size=1, max_size=20))
    def test_cookiejar_contains_all_set_cookies(self, cookies: dict) -> None:
        """All set cookies should be in the jar."""
        jar = RequestsCookieJar()
        for name, value in cookies.items():
            jar.set(name, value)
        for name in cookies:
            assert name in jar

    @given(st.dictionaries(cookie_names, cookie_values, max_size=20))
    def test_cookiejar_pickleable_roundtrip(self, cookies: dict) -> None:
        """RequestsCookieJar should be pickleable."""
        import pickle

        jar = cookiejar_from_dict(cookies)
        state = jar.__getstate__()
        new_jar = RequestsCookieJar()
        new_jar.__setstate__(state)
        # Should have same cookies
        assert len(new_jar) == len(jar)


class TestCookieSetNoneValue:
    """Test setting None as cookie value."""

    @given(cookie_names)
    def test_set_none_removes_cookie(self, name: str) -> None:
        """Setting cookie to None should remove it."""
        jar = RequestsCookieJar()
        jar.set(name, "some_value")
        assert name in jar
        jar.set(name, None)
        assert name not in jar

    @given(cookie_names, cookie_values)
    def test_set_none_on_nonexistent_cookie(self, name: str, value: str) -> None:
        """Setting None on nonexistent cookie should not raise."""
        jar = RequestsCookieJar()
        jar.set(name, None)  # Should not raise
        assert name not in jar


class TestCookieJarListMethods:
    """Test list_* methods of RequestsCookieJar."""

    @given(
        st.lists(
            st.tuples(
                cookie_names,
                cookie_values,
                st.text(
                    alphabet=st.characters(
                        min_codepoint=ord("a"), max_codepoint=ord("z")
                    ),
                    min_size=1,
                    max_size=20,
                ),
            ),
            min_size=1,
            max_size=10,
        )
    )
    def test_list_domains(self, cookies_with_domains: list) -> None:
        """list_domains() should return all unique domains."""
        jar = RequestsCookieJar()
        domains = set()
        for name, value, domain in cookies_with_domains:
            jar.set(name, value, domain=domain)
            domains.add(domain)
        result_domains = jar.list_domains()
        assert len(result_domains) >= 1
        # All domains should be represented
        for domain in domains:
            assert domain in result_domains

    @given(
        st.lists(
            st.tuples(cookie_names, cookie_values, st.text(min_size=1, max_size=20)),
            min_size=1,
            max_size=10,
        )
    )
    def test_list_paths(self, cookies_with_paths: list) -> None:
        """list_paths() should return all unique paths."""
        jar = RequestsCookieJar()
        paths = set()
        for name, value, path in cookies_with_paths:
            jar.set(name, value, path=path)
            paths.add(path)
        result_paths = jar.list_paths()
        assert len(result_paths) >= 1
        # All paths should be represented
        for path in paths:
            assert path in result_paths

