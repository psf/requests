import pytest

from requests import hooks


def hook(value):
    return value[1:]


@pytest.mark.parametrize(
    "hooks_list, result",
    (
        (hook, "ata"),
        ([hook, lambda x: None, hook], "ta"),
    ),
)
def test_hooks(hooks_list, result):
    assert hooks.dispatch_hook("response", {"response": hooks_list}, "Data") == result


def test_default_hooks():
    assert hooks.default_hooks() == {"response": []}


def test_hooks_with_multiple_hooks():
    def hook1(value):
        return value + "1"

    def hook2(value):
        return value + "2"

    hooks_list = [hook1, hook2]
    result = hooks.dispatch_hook("response", {"response": hooks_list}, "Data")
    assert result == "Data12"


def test_hooks_with_no_hooks():
    hooks_list = []
    result = hooks.dispatch_hook("response", {"response": hooks_list}, "Data")
    assert result == "Data"
