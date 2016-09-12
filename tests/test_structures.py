# -*- coding: utf-8 -*-

import pytest

from requests.structures import CaseInsensitiveDict, LookupDict


class TestCaseInsensitiveDict:

    @pytest.fixture(autouse=True)
    def setup(self):
        """CaseInsensitiveDict instance with "Accept" header."""
        self.case_insensitive_dict = CaseInsensitiveDict()
        self.case_insensitive_dict['Accept'] = 'application/json'

    def test_list(self):
        assert list(self.case_insensitive_dict) == ['Accept']

    possible_keys = pytest.mark.parametrize('key', ('accept', 'ACCEPT', 'aCcEpT', 'Accept'))

    @possible_keys
    def test_getitem(self, key):
        assert self.case_insensitive_dict[key] == 'application/json'

    @possible_keys
    def test_delitem(self, key):
        del self.case_insensitive_dict[key]
        assert key not in self.case_insensitive_dict

    def test_lower_items(self):
        assert list(self.case_insensitive_dict.lower_items()) == [('accept', 'application/json')]

    def test_repr(self):
        assert repr(self.case_insensitive_dict) == "{'Accept': 'application/json'}"

    def test_copy(self):
        copy = self.case_insensitive_dict.copy()
        assert copy is not self.case_insensitive_dict
        assert copy == self.case_insensitive_dict

    @pytest.mark.parametrize(
        'other, result', (
            ({'AccePT': 'application/json'}, True),
            ({}, False),
            (None, False)
        )
    )
    def test_instance_equality(self, other, result):
        assert (self.case_insensitive_dict == other) is result


class TestLookupDict:

    @pytest.fixture(autouse=True)
    def setup(self):
        """LookupDict instance with "bad_gateway" attribute."""
        self.lookup_dict = LookupDict('test')
        self.lookup_dict.bad_gateway = 502

    def test_repr(self):
        assert repr(self.lookup_dict) == "<lookup 'test'>"

    get_item_parameters = pytest.mark.parametrize(
        'key, value', (
            ('bad_gateway', 502),
            ('not_a_key', None)
        )
    )

    @get_item_parameters
    def test_getitem(self, key, value):
        assert self.lookup_dict[key] == value

    @get_item_parameters
    def test_get(self, key, value):
        assert self.lookup_dict.get(key) == value
