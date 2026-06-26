import pytest

from requests.structures import CaseInsensitiveDict, LookupDict


class TestCaseInsensitiveDict:
    @pytest.fixture(autouse=True)
    def setup(self):
        """CaseInsensitiveDict instance with "Accept" header."""
        self.case_insensitive_dict = CaseInsensitiveDict()
        self.case_insensitive_dict["Accept"] = "application/json"

    def test_list(self):
        assert list(self.case_insensitive_dict) == ["Accept"]

    possible_keys = pytest.mark.parametrize(
        "key", ("accept", "ACCEPT", "aCcEpT", "Accept")
    )

    @possible_keys
    def test_getitem(self, key):
        assert self.case_insensitive_dict[key] == "application/json"

    @possible_keys
    def test_delitem(self, key):
        del self.case_insensitive_dict[key]
        assert key not in self.case_insensitive_dict

    def test_lower_items(self):
        assert list(self.case_insensitive_dict.lower_items()) == [
            ("accept", "application/json")
        ]

    def test_repr(self):
        assert repr(self.case_insensitive_dict) == "{'Accept': 'application/json'}"

    def test_copy(self):
        copy = self.case_insensitive_dict.copy()
        assert copy is not self.case_insensitive_dict
        assert copy == self.case_insensitive_dict

    @pytest.mark.parametrize(
        "other, result",
        (
            ({"AccePT": "application/json"}, True),
            ({}, False),
            (None, False),
        ),
    )
    def test_instance_equality(self, other, result):
        assert (self.case_insensitive_dict == other) is result


class TestLookupDict:
    @pytest.fixture(autouse=True)
    def setup(self):
        """LookupDict instance with "bad_gateway" attribute."""
        self.lookup_dict = LookupDict("test")
        self.lookup_dict.bad_gateway = 502

    def test_repr(self):
        assert repr(self.lookup_dict) == "<lookup 'test'>"

    get_item_parameters = pytest.mark.parametrize(
        "key, value",
        (
            ("bad_gateway", 502),
            ("not_a_key", None),
        ),
    )

    @get_item_parameters
    def test_getitem(self, key, value):
        assert self.lookup_dict[key] == value

    @get_item_parameters
    def test_get(self, key, value):
        assert self.lookup_dict.get(key) == value

    def test_hasattr(self):
        assert hasattr(self.lookup_dict, "bad_gateway") is True
        assert hasattr(self.lookup_dict, "not_a_key") is False

    def test_getattr(self):
        assert getattr(self.lookup_dict, "bad_gateway") == 502
        with pytest.raises(AttributeError):
            getattr(self.lookup_dict, "not_a_key")

    @get_item_parameters
    def test_getattr_default(self, key, value):
        assert getattr(self.lookup_dict, key, None) == value


class TestCaseInsensitiveDictKeyValidation:
    """
    `CaseInsensitiveDict` keys must be strings (or bytes decodable as
    utf-8). The old implementation called `.lower()` on every key without
    a type check, so passing an int or undecodable bytes produced a
    confusing `AttributeError: 'int' object has no attribute 'lower'`
    from inside the implementation instead of a clean `TypeError` at
    the call site.
    """

    @pytest.mark.parametrize("bad_key", [1, 3.14, None, ("a",), object()])
    def test_setitem_rejects_non_string_keys(self, bad_key):
        cid = CaseInsensitiveDict()
        with pytest.raises(TypeError) as excinfo:
            cid[bad_key] = "x"
        assert "CaseInsensitiveDict" in str(excinfo.value)

    def test_setitem_rejects_non_utf8_bytes(self):
        cid = CaseInsensitiveDict()
        with pytest.raises(TypeError) as excinfo:
            cid[b"\xff\xfe"] = "x"
        assert "CaseInsensitiveDict" in str(excinfo.value)

    @pytest.mark.parametrize("bad_key", [1, None, object()])
    def test_getitem_rejects_non_string_keys(self, bad_key):
        cid = CaseInsensitiveDict({"Accept": "application/json"})
        with pytest.raises(TypeError):
            _ = cid[bad_key]

    @pytest.mark.parametrize("bad_key", [1, None, object()])
    def test_delitem_rejects_non_string_keys(self, bad_key):
        cid = CaseInsensitiveDict({"Accept": "application/json"})
        with pytest.raises(TypeError):
            del cid[bad_key]

    def test_contains_returns_false_for_non_string_keys(self):
        # `in` is a membership test, so it should not raise - it should
        # simply return False for keys the dict cannot store.
        cid = CaseInsensitiveDict({"Accept": "application/json"})
        assert (1 in cid) is False
        assert (None in cid) is False
        assert (object() in cid) is False
        # Strings (and bytes) continue to behave normally.
        assert ("accept" in cid) is True
        assert ("ACCEPT" in cid) is True

    def test_init_rejects_mapping_with_non_string_keys(self):
        with pytest.raises(TypeError) as excinfo:
            CaseInsensitiveDict({1: "one"})
        assert "CaseInsensitiveDict" in str(excinfo.value)

    def test_init_rejects_iterable_with_non_string_pairs(self):
        with pytest.raises(TypeError) as excinfo:
            CaseInsensitiveDict([(1, "one")])
        assert "CaseInsensitiveDict" in str(excinfo.value)

    def test_init_rejects_non_utf8_bytes_keys(self):
        with pytest.raises(TypeError):
            CaseInsensitiveDict({b"\xff\xfe": "value"})

    def test_init_accepts_utf8_bytes_keys(self):
        cid = CaseInsensitiveDict({b"Accept": "application/json"})
        assert cid["accept"] == "application/json"

    def test_update_rejects_non_string_keys(self):
        cid = CaseInsensitiveDict()
        with pytest.raises(TypeError):
            cid.update({1: "one"})

    def test_eq_returns_false_for_mapping_with_non_string_keys(self):
        # Comparing against a Mapping whose keys cannot be stored in a
        # CaseInsensitiveDict must return False, not raise. The old
        # implementation constructed `CaseInsensitiveDict(other)` which
        # raised AttributeError on `key.lower()`.
        cid = CaseInsensitiveDict({"Accept": "application/json"})
        assert (cid == {1: "one"}) is False
        # Symmetric direction: the right-hand operand does not know
        # about CaseInsensitiveDict and just falls back to identity.
        assert ({1: "one"} == cid) is False

    def test_eq_returns_notimplemented_for_non_mapping(self):
        # Already covered by `test_instance_equality` but pin the
        # explicit return for non-Mapping scalars too.
        cid = CaseInsensitiveDict({"Accept": "application/json"})
        assert (cid == "Accept: application/json") is False
        assert (cid == 42) is False
        assert (cid == [("Accept", "application/json")]) is False

    def test_eq_equivalent_string_mappings_still_work(self):
        cid = CaseInsensitiveDict({"Accept": "application/json"})
        assert cid == {"accept": "application/json"}
        assert cid == {"ACCEPT": "application/json"}
