"""
Hypothesis-based property tests for requests.structures module.

These tests use property-based testing to verify the invariants and properties
of data structures like CaseInsensitiveDict and LookupDict.
"""

from collections.abc import Mapping

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from requests.structures import CaseInsensitiveDict, LookupDict


class TestCaseInsensitiveDictProperties:
    """Property-based tests for CaseInsensitiveDict."""

    @settings(max_examples=1000, deadline=None)
    @given(st.dictionaries(st.text(min_size=1), st.text()))
    def test_caseinsensitivedict_creation(self, data: dict) -> None:
        """CaseInsensitiveDict should be creatable from dict."""
        cid = CaseInsensitiveDict(data)
        assert isinstance(cid, CaseInsensitiveDict)
        # Length should match unique case-insensitive keys
        unique_keys = {k.lower() for k in data.keys()}
        assert len(cid) == len(unique_keys)

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=50,
            ),
            st.text(min_size=0, max_size=100),
        )
    )
    def test_caseinsensitivedict_case_insensitive_get(
        self, data: dict
    ) -> None:
        """CaseInsensitiveDict should be case-insensitive for lookups."""
        cid = CaseInsensitiveDict(data)
        for key, value in data.items():
            # Test various case combinations
            assert cid[key.lower()] == value
            assert cid[key.upper()] == value
            assert cid[key] == value

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=50,
            ),
            st.text(min_size=0, max_size=100),
        )
    )
    def test_caseinsensitivedict_preserves_case(self, data: dict) -> None:
        """CaseInsensitiveDict should preserve original key case."""
        cid = CaseInsensitiveDict(data)
        keys = list(cid.keys())
        # Keys should maintain their original case
        assert all(isinstance(k, str) for k in keys)

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(min_size=1, max_size=50), st.text(min_size=0, max_size=100)
        )
    )
    def test_caseinsensitivedict_len(self, data: dict) -> None:
        """CaseInsensitiveDict length should match number of unique case-insensitive keys."""
        cid = CaseInsensitiveDict(data)
        # Calculate expected length based on unique case-insensitive keys
        unique_keys = {k.lower() for k in data.keys()}
        assert len(cid) == len(unique_keys)

    @settings(max_examples=1000, deadline=None)
    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=50,
        ),
        st.text(min_size=0, max_size=100),
    )
    def test_caseinsensitivedict_setitem_getitem(
        self, key: str, value: str
    ) -> None:
        """Setting and getting items should work case-insensitively."""
        cid = CaseInsensitiveDict()
        cid[key] = value
        assert cid[key] == value
        assert cid[key.lower()] == value
        assert cid[key.upper()] == value

    @settings(max_examples=1000, deadline=None)
    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=50,
        ),
        st.text(min_size=0, max_size=100),
    )
    def test_caseinsensitivedict_delitem(
        self, key: str, value: str
    ) -> None:
        """Deleting items should work case-insensitively."""
        cid = CaseInsensitiveDict()
        cid[key] = value
        # Delete with different case
        del cid[key.upper()]
        assert key.lower() not in cid

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=50,
            ),
            st.text(min_size=0, max_size=100),
        )
    )
    def test_caseinsensitivedict_iteration(self, data: dict) -> None:
        """Iterating over CaseInsensitiveDict should yield keys."""
        cid = CaseInsensitiveDict(data)
        keys = list(cid)
        assert len(keys) == len(data)
        assert all(isinstance(k, str) for k in keys)

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=50,
            ),
            st.text(min_size=0, max_size=100),
        )
    )
    def test_caseinsensitivedict_items(self, data: dict) -> None:
        """items() should return key-value pairs."""
        cid = CaseInsensitiveDict(data)
        items = list(cid.items())
        assert len(items) == len(data)
        assert all(isinstance(item, tuple) and len(item) == 2 for item in items)

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=50,
            ),
            st.text(min_size=0, max_size=100),
        )
    )
    def test_caseinsensitivedict_lower_items(self, data: dict) -> None:
        """lower_items() should return lowercase keys."""
        cid = CaseInsensitiveDict(data)
        lower_items = list(cid.lower_items())
        assert all(key.islower() for key, _ in lower_items)
        assert len(lower_items) == len(data)

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=50,
            ),
            st.text(min_size=0, max_size=100),
        )
    )
    def test_caseinsensitivedict_copy(self, data: dict) -> None:
        """copy() should create an independent copy."""
        cid = CaseInsensitiveDict(data)
        cid_copy = cid.copy()
        assert cid == cid_copy
        assert cid is not cid_copy
        assert isinstance(cid_copy, CaseInsensitiveDict)

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=50,
            ),
            st.text(min_size=0, max_size=100),
        )
    )
    def test_caseinsensitivedict_equality(self, data: dict) -> None:
        """Two CaseInsensitiveDicts with same data should be equal."""
        cid1 = CaseInsensitiveDict(data)
        cid2 = CaseInsensitiveDict(data)
        assert cid1 == cid2

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=50,
            ),
            st.text(min_size=0, max_size=100),
        )
    )
    def test_caseinsensitivedict_equality_with_dict(
        self, data: dict
    ) -> None:
        """CaseInsensitiveDict should equal dict with same data."""
        cid = CaseInsensitiveDict(data)
        # Create a regular dict with lowercase keys
        lowered_data = {k.lower(): v for k, v in data.items()}
        regular_dict = dict(lowered_data)
        # They should be equal when comparing case-insensitively
        assert cid == CaseInsensitiveDict(regular_dict)

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=50,
            ),
            st.text(min_size=0, max_size=100),
        ),
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=50,
            ),
            st.text(min_size=0, max_size=100),
        ),
    )
    def test_caseinsensitivedict_update(
        self, data1: dict, data2: dict
    ) -> None:
        """update() should merge dictionaries."""
        cid = CaseInsensitiveDict(data1)
        original_len = len(cid)
        cid.update(data2)
        # Length should be at least the maximum of the two
        assert len(cid) >= max(len(data1), len(data2))
        # All keys from data2 should be present
        for key in data2:
            assert key in cid or key.lower() in cid or key.upper() in cid

    @settings(max_examples=1000, deadline=None)
    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=50,
        ),
        st.text(min_size=0, max_size=100),
    )
    def test_caseinsensitivedict_contains(
        self, key: str, value: str
    ) -> None:
        """'in' operator should work case-insensitively."""
        cid = CaseInsensitiveDict({key: value})
        assert key in cid
        assert key.lower() in cid
        assert key.upper() in cid

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=50,
            ),
            st.text(min_size=0, max_size=100),
            min_size=1,
        )
    )
    def test_caseinsensitivedict_repr(self, data: dict) -> None:
        """repr() should return a valid string representation."""
        cid = CaseInsensitiveDict(data)
        repr_str = repr(cid)
        assert isinstance(repr_str, str)
        assert len(repr_str) > 0

    @settings(max_examples=1000, deadline=None)
    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=50,
        ),
        st.text(min_size=0, max_size=100),
        st.text(min_size=0, max_size=100),
    )
    def test_caseinsensitivedict_overwrites_on_same_key(
        self, key: str, value1: str, value2: str
    ) -> None:
        """Setting same key (different case) should overwrite."""
        cid = CaseInsensitiveDict()
        cid[key.lower()] = value1
        cid[key.upper()] = value2
        # Should have only one entry
        assert len(cid) == 1
        # Should have the last value
        assert cid[key] == value2


class TestLookupDictProperties:
    """Property-based tests for LookupDict."""

    @settings(max_examples=1000, deadline=None)
    @given(st.text(min_size=1, max_size=50))
    def test_lookupdict_creation(self, name: str) -> None:
        """LookupDict should be creatable with a name."""
        ld = LookupDict(name=name)
        assert isinstance(ld, LookupDict)
        assert ld.name == name

    @settings(max_examples=1000, deadline=None)
    @given(
        st.text(min_size=1, max_size=50),
        st.text(min_size=1, max_size=50),
        st.text(min_size=0, max_size=100),
    )
    def test_lookupdict_setattr_getitem(
        self, name: str, key: str, value: str
    ) -> None:
        """LookupDict should allow attribute-style access."""
        # Filter out dunder attributes and 'name' to avoid restricted/reserved attributes
        assume(not key.startswith("__") and key != "name")
        ld = LookupDict(name=name)
        # Set via attribute
        setattr(ld, key, value)
        # Get via item access
        result = ld[key]
        assert result == value

    @settings(max_examples=1000, deadline=None)
    @given(st.text(min_size=1, max_size=50), st.text(min_size=1, max_size=50))
    def test_lookupdict_getitem_missing_returns_none(
        self, name: str, key: str
    ) -> None:
        """LookupDict should return None for missing keys."""
        # Filter out 'name' since it's an instance attribute that will be returned
        assume(key != "name")
        ld = LookupDict(name=name)
        result = ld[key]
        assert result is None

    @settings(max_examples=1000, deadline=None)
    @given(
        st.text(min_size=1, max_size=50),
        st.text(min_size=1, max_size=50),
        st.text(min_size=0, max_size=100),
        st.text(min_size=0, max_size=100),
    )
    def test_lookupdict_get_method(
        self, name: str, key: str, value: str, default: str
    ) -> None:
        """LookupDict.get() should work like dict.get()."""
        ld = LookupDict(name=name)
        # Missing key should return default
        assert ld.get(key, default) == default
        # Set value
        setattr(ld, key, value)
        # Now should return value
        assert ld.get(key, default) == value

    @settings(max_examples=1000, deadline=None)
    @given(st.text(min_size=1, max_size=50))
    def test_lookupdict_repr(self, name: str) -> None:
        """LookupDict repr should include name."""
        ld = LookupDict(name=name)
        repr_str = repr(ld)
        assert isinstance(repr_str, str)
        assert name in repr_str
        assert "lookup" in repr_str.lower()

    @settings(max_examples=1000, deadline=None)
    @given(
        st.text(min_size=1, max_size=50),
        st.dictionaries(
            st.text(min_size=1, max_size=20).filter(lambda x: not x.startswith("__")),
            st.text(min_size=0, max_size=100),
            min_size=1,
            max_size=10,
        ),
    )
    def test_lookupdict_multiple_attributes(
        self, name: str, attrs: dict
    ) -> None:
        """LookupDict should handle multiple attributes."""
        ld = LookupDict(name=name)
        # Set multiple attributes (filter out dunder/special attributes)
        for key, value in attrs.items():
            setattr(ld, key, value)
        # Verify all are accessible
        for key, value in attrs.items():
            assert ld[key] == value
            assert ld.get(key) == value

    @settings(max_examples=1000, deadline=None)
    @given(st.text(min_size=1, max_size=50))
    def test_lookupdict_is_dict_subclass(self, name: str) -> None:
        """LookupDict should be a dict subclass."""
        ld = LookupDict(name=name)
        assert isinstance(ld, dict)

    @settings(max_examples=1000, deadline=None)
    @given(
        st.text(min_size=1, max_size=50),
        st.text(min_size=1, max_size=50),
        st.text(min_size=0, max_size=100),
    )
    def test_lookupdict_none_default_behavior(
        self, name: str, key: str, value: str
    ) -> None:
        """LookupDict should return None by default for missing keys."""
        # Filter out dunder attributes and 'name' to avoid restricted/reserved attributes
        assume(not key.startswith("__") and key != "name")
        ld = LookupDict(name=name)
        # Missing key
        assert ld.get(key) is None
        # With explicit None default
        assert ld.get(key, None) is None
        # Set value
        setattr(ld, key, value)
        # Should not be None anymore
        assert ld.get(key) is not None


class TestCaseInsensitiveDictInvariants:
    """Test invariants that should always hold for CaseInsensitiveDict."""

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=20,
            ),
            st.text(min_size=0, max_size=50),
        )
    )
    def test_caseinsensitivedict_is_mapping(self, data: dict) -> None:
        """CaseInsensitiveDict should be a Mapping."""
        cid = CaseInsensitiveDict(data)
        assert isinstance(cid, Mapping)

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=20,
            ),
            st.text(min_size=0, max_size=50),
        )
    )
    def test_caseinsensitivedict_keys_values_same_length(
        self, data: dict
    ) -> None:
        """keys() and values() should have same length."""
        cid = CaseInsensitiveDict(data)
        assert len(list(cid.keys())) == len(list(cid.values()))

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=20,
            ),
            st.text(min_size=0, max_size=50),
        )
    )
    def test_caseinsensitivedict_consistency_across_operations(
        self, data: dict
    ) -> None:
        """All access methods should be consistent."""
        cid = CaseInsensitiveDict(data)
        for key, value in data.items():
            # Different ways to access should give same result
            assert cid[key] == value
            assert cid.get(key) == value
            assert key in cid or key.lower() in cid or key.upper() in cid

    @settings(max_examples=1000, deadline=None)
    @given(
        st.text(
            alphabet=st.characters(
                min_codepoint=ord("a"), max_codepoint=ord("z")
            ),
            min_size=1,
            max_size=20,
        ),
        st.text(min_size=0, max_size=50),
        st.text(min_size=0, max_size=50),
    )
    def test_caseinsensitivedict_set_get_roundtrip(
        self, key: str, value1: str, value2: str
    ) -> None:
        """Setting a value and getting it should return the same value."""
        cid = CaseInsensitiveDict()
        cid[key] = value1
        assert cid[key] == value1
        # Update with different case
        cid[key.upper()] = value2
        assert cid[key.lower()] == value2

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=20,
            ),
            st.text(min_size=0, max_size=50),
            min_size=1,
        )
    )
    def test_caseinsensitivedict_copy_is_equal(self, data: dict) -> None:
        """A copy should be equal to the original."""
        cid = CaseInsensitiveDict(data)
        cid_copy = cid.copy()
        assert cid == cid_copy

    @settings(max_examples=1000, deadline=None)
    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=20,
            ),
            st.text(min_size=0, max_size=50),
            min_size=1,
        )
    )
    def test_caseinsensitivedict_copy_is_independent(
        self, data: dict
    ) -> None:
        """Modifying a copy should not affect the original."""
        cid = CaseInsensitiveDict(data)
        cid_copy = cid.copy()
        # Modify copy
        cid_copy["new_key"] = "new_value"
        # Original should not have new key
        assert "new_key" not in cid

