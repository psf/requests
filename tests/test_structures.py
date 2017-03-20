# -*- coding: utf-8 -*-

import pytest

from requests.structures import CaseInsensitiveDict, LookupDict, TimedCache, TimedCacheManaged


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


class TestTimedCache(object):
    @pytest.fixture(autouse=True)
    def setup(self):
        self.any_value = 'some value'
        self.expiration_secs = 60
        self.cache = TimedCache(expiration_secs=self.expiration_secs)
        yield
        self.cache.clear()

    def test_get(self):
        self.cache['a'] = self.any_value
        assert self.cache['a'] is self.any_value

    def test_repr(self):
        repr = str(self.cache)
        assert repr == '<TimedCache maxlen:32 len:0 expiration_secs:60>'

    def test_get_expired_item(self, mocker):
        self.cache = TimedCache(maxlen=1, expiration_secs=self.expiration_secs)

        mocker.patch('requests.structures.current_time', lambda: 0)
        self.cache['a'] = self.any_value
        mocker.patch('requests.structures.current_time', lambda: self.expiration_secs + 1)
        assert self.cache.get('a') is None

    def test_evict_first_entry_when_full(self, mocker):
        self.cache = TimedCache(maxlen=2, expiration_secs=2)
        mocker.patch('requests.structures.current_time', lambda: 0)
        self.cache['a'] = self.any_value
        mocker.patch('requests.structures.current_time', lambda: 1)
        self.cache['b'] = self.any_value
        mocker.patch('requests.structures.current_time', lambda: 3)
        self.cache['c'] = self.any_value
        assert len(self.cache) is 2
        with pytest.raises(KeyError, message='Expected key not found'):
            self.cache['a']
        assert self.cache['b'] is self.any_value
        assert self.cache['c'] is self.any_value

    def test_delete_item_removes_item(self):
        self.cache['a'] = self.any_value
        del self.cache['a']
        with pytest.raises(KeyError, message='Expected key not found'):
            self.cache['a']

    def test_iterating_hides_timestamps(self):
        self.cache['a'] = 1
        self.cache['b'] = 2
        expected = [('a', 1), ('b', 2)]
        actual = [(key, val) for key, val in self.cache]
        assert expected == actual


class TestTimedCacheManagedDecorator(object):
    def test_caches_repeated_calls(self, mocker):
        mocker.patch('requests.structures.current_time', lambda: 0)

        nonlocals = {'value': 0}

        @TimedCacheManaged
        def some_method(x):
            nonlocals['value'] = nonlocals['value'] + x
            return nonlocals['value']

        first_result = some_method(1)
        assert first_result is 1
        second_result = some_method(1)
        assert second_result is 1
        third_result = some_method(2)
        assert third_result is 3
