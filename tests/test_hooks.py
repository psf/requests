import pytest

from requests import hooks


def hook(value):
    return value[1:]


@pytest.mark.parametrize(
    "hooks_list, result",
    (
        (hook, "ata"),
        ([hook, lambda x: None, hook], "ta"),
@pytest.mark.parametrize(
    "hooks_list, result",
    (
        (hook, "ata" if hook("Data") == "ata" else "Data"),
        ([hook, lambda x: None, hook], "ta"),
    ),
)
    assert hooks.default_hooks() == {"response": []}
