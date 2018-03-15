# -*- coding: utf-8 -*-
import pytest

from requests.structures import CaseInsensitiveDict, LookupDict, HTTPHeaderDict
from urllib3._collections import HTTPHeaderDict as U3HeaderDict


class TestCaseInsensitiveDict:

    @pytest.fixture(autouse=True)
    def setup(self):
        """CaseInsensitiveDict instance with "Accept" header."""
        self.case_insensitive_dict = CaseInsensitiveDict()
        self.case_insensitive_dict['Accept'] = 'application/json'

    def test_list(self):
        assert list(self.case_insensitive_dict) == ['Accept']

    possible_keys = pytest.mark.parametrize(
        'key', ('accept', 'ACCEPT', 'aCcEpT', 'Accept')
    )

    @possible_keys
    def test_getitem(self, key):
        assert self.case_insensitive_dict[key] == 'application/json'

    @possible_keys
    def test_delitem(self, key):
        del self.case_insensitive_dict[key]
        assert key not in self.case_insensitive_dict

    def test_lower_items(self):
        assert list(self.case_insensitive_dict.lower_items()) == [
            ('accept', 'application/json')
        ]

    def test_repr(self):
        assert repr(
            self.case_insensitive_dict
        ) == "{'Accept': 'application/json'}"

    def test_copy(self):
        copy = self.case_insensitive_dict.copy()
        assert copy is not self.case_insensitive_dict
        assert copy == self.case_insensitive_dict

    @pytest.mark.parametrize(
        'other, result',
        (({'AccePT': 'application/json'}, True), ({}, False), (None, False)),
    )
    def test_instance_equality(self, other, result):
        assert (self.case_insensitive_dict == other) is result


class TestHTTPHeaderDictCompatibility(TestCaseInsensitiveDict):

    """HTTPHeaderDict should be completely compatible with CaseInsensitiveDict
    when used for headers, so ensure that all the tests for the base class
    also pass for this one."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.case_insensitive_dict = HTTPHeaderDict()
        self.case_insensitive_dict['Accept'] = 'application/json'


class TestHTTPHeaderDict:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.kvs = [
            ('animal', 'chicken'),
            ('AnimaL', 'Cow'),
            ('CAKE', 'Cheese!'),
            ('Sauce', 'Bread'),
            ('Sauce', 'Cherry, or Plum Tomato'),
        ]

        # HTTPHeaderDict from urllib3.
        self.u3dict = ud = U3HeaderDict()
        [ud.add(*tpl) for tpl in self.kvs]

        # Regular dictionary.
        self.ddict = dict(self.kvs)
        self.ddict['Sauce'] = ['Bread!', 'Cherry, or Plum Tomato']

        # Used by test_extend. All of these "extra" values are mostly
        # equivalent to each other.
        self.extra_hd = hd2 = HTTPHeaderDict(ANIMAL=['Dog', 'elephant'])
        hd2['cake'] = 'Babka'
        hd2.setlist('sound', ['quiet', 'LOUD'])
        hd2['CUTLERY'] = 'fork'

        self.extra_tuple_pairs = tuple_pairs = [
            ('ANIMAL', 'Dog'),
            ('Animal', 'elephant'),
            ('cake', ['Babka']),
            ('sound', 'quiet'),
            ('sound', 'LOUD'),
            ('CUTLERY', 'fork'),
        ]

        self.extra_simple_dict = dict(tuple_pairs)
        self.extra_simple_dict['sound'] = ('quiet', 'LOUD')

        self.extra_u3 = U3HeaderDict()
        for k, v in tuple_pairs:
            if isinstance(v, (tuple, list)):
                for vi in v:
                    self.extra_u3.add(k, vi)
            else:
                self.extra_u3.add(k, v)

    def test_item_access(self):
        hd = HTTPHeaderDict(self.kvs)

        # Test that values are combined.
        assert hd['Sauce'] == 'Bread, Cherry, or Plum Tomato'
        assert hd['ANIMAL'] == 'chicken, Cow'

        # Test we can overwrite values.
        hd['animal'] = 'Goat!'
        assert hd['anIMal'] == 'Goat!'

        # Test deletion works.
        del hd['sauce']
        pytest.raises(KeyError, hd.__getitem__, 'sauce')

        # Only string types allowed.
        pytest.raises(ValueError, hd.__setitem__, 'cake', ['Cheese', 'sponge'])

    def test_equality(self):
        hd = HTTPHeaderDict(self.u3dict)
        assert hd == self.u3dict
        assert hd == HTTPHeaderDict(hd)

        # Test that we still work even if we are comparing to a
        # CaseInsensitiveDict instance.
        cid = CaseInsensitiveDict(hd)
        assert hd == cid
        assert cid == hd

    def test_lower_items(self):
        hd = HTTPHeaderDict(self.kvs, cutlery='fork')
        assert list(hd.lower_items()) == [
            ('animal', 'chicken, Cow'),
            ('cake', 'Cheese!'),
            ('sauce', 'Bread, Cherry, or Plum Tomato'),
            ('cutlery', 'fork'),
        ]

    def test_copy(self):
        hd = HTTPHeaderDict(self.u3dict)
        hd2 = hd.copy()
        assert hd is not hd2
        assert hd == hd2

    def test_get_and_set_list(self):
        hd = HTTPHeaderDict(self.kvs)
        assert hd.getlist('SAUCE') == ['Bread', 'Cherry, or Plum Tomato']
        assert hd.getlist('CAKE') == ['Cheese!']
        assert hd.getlist('DRINK') == []

        # Needs to be a regular sequence type containing just strings.
        pytest.raises(ValueError, hd.setlist, 'Drink', 'Water')
        pytest.raises(ValueError, hd.setlist, 'Drink', ['H', 2, 'O'])

        # Test multi-setting.
        hd.setlist('Drink', ['Water', 'Juice'])
        assert hd.getlist('DRINK') == ['Water', 'Juice']

        # Setting to an empty sequence should remove the entry.
        hd.setlist('DRInk', [])
        pytest.raises(KeyError, hd.__getitem__, 'DrinK')
        assert hd.getlist('DRiNK') == []

    def test_add(self):
        hd = HTTPHeaderDict()
        hd.add('sound', 'quiet')
        hd.add('SOUND', 'LOUD')
        assert hd.getlist('Sound') == ['quiet', 'LOUD']

        # Enforce type-checking in the add method.
        pytest.raises(ValueError, hd.add, 'Sound', 5)

    @pytest.mark.parametrize('attr,as_arg,animal_arg_is_ordered', [
        # These types will have the "animal" arguments in our preferred order.
        ('extra_hd', True, True),
        ('extra_tuple_pairs', True, True),

        # And these types will lose the ordering, so we can't make assertions
        # about the final order of those values.
        ('extra_simple_dict', True, False),
        ('extra_u3', True, False),
        ('extra_simple_dict', False, False),
    ])
    def test_extend(self, attr, as_arg, animal_arg_is_ordered):
        item = getattr(self, attr)

        # Call extend with the associated values - we should see all of the
        # merged data in the HTTPHeaderDict instance.
        extras = {'cutlery': 'knife'}
        hd = HTTPHeaderDict(self.kvs)

        if as_arg:
            hd.extend(item, **extras)
        else:
            hd.extend(extras, **item)

        # Test all the stored values are what we expect.
        mget = hd.getlist

        # Depending on the item we merged in, we might be able to make
        # assumptions what the overall order of the structure is.
        animal_seq = mget('animal')
        if animal_arg_is_ordered:
            assert animal_seq == ['chicken', 'Cow', 'Dog', 'elephant']
        else:
            # The existing order in HTTPHeadersDict of the first two values
            # should be preserved - no guarantees in which order the other
            # two values are added.
            assert animal_seq in [
                ['chicken', 'Cow', 'Dog', 'elephant'],
                ['chicken', 'Cow', 'elephant', 'Dog']
            ]

        assert mget('cake') == ['Cheese!', 'Babka']
        assert mget('sound') == ['quiet', 'LOUD']

        # We don't mandate the order in which these dictionaries are
        # processed, so it's fine whichever order it is.
        assert mget('cutlery') in [
            ['fork', 'knife'], ['knife', 'fork']
        ]

    def test_extend_type_checking(self):
        hd = HTTPHeaderDict()
        pytest.raises(ValueError, hd.extend, dict(type=['xml', None, 'html']))

    def test_repr(self):
        hd = HTTPHeaderDict()
        assert repr(hd) == '{}'
        hd.add('type', 'xml')
        assert repr(hd) == "{'type': 'xml'}"
        hd.add('type', 'html')
        assert repr(hd) == "{'type': ('xml', 'html')}"

        # We can't guarantee order once we have more than one key.
        hd.add('Accept', 'text/html')
        assert repr(hd) in [
            "{'type': ('xml', 'html'), 'Accept': 'text/html'}",
            "{'Accept': 'text/html', 'type': ('xml', 'html')}",
        ]
        assert str(hd) == repr(hd)


class TestLookupDict:

    @pytest.fixture(autouse=True)
    def setup(self):
        """LookupDict instance with "bad_gateway" attribute."""
        self.lookup_dict = LookupDict('test')
        self.lookup_dict.bad_gateway = 502

    def test_repr(self):
        assert repr(self.lookup_dict) == "<lookup 'test'>"

    get_item_parameters = pytest.mark.parametrize(
        'key, value', (('bad_gateway', 502), ('not_a_key', None))
    )

    @get_item_parameters
    def test_getitem(self, key, value):
        assert self.lookup_dict[key] == value

    @get_item_parameters
    def test_get(self, key, value):
        assert self.lookup_dict.get(key) == value
