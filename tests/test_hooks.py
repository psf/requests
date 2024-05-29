# -*- coding: utf-8 -*-

import pytest

from requests import hooks


def hook(value):
    return value[1:]


@pytest.mark.parametrize(
    'hooks_list, result', (
        (hook, 'ata'),
        ([hook, lambda x: None, hook], 'ta'),
    )
)
def test_hooks(hooks_list, result):
    assert hooks.dispatch_hook('response', {'response': hooks_list}, 'Data') == result


def test_default_hooks():
    assert hooks.default_hooks() == {'response': []}
