import pytest
import simplejson
import json

from requests import get, JSONDecodeError

success_url = "https://httpbin.org/get"  # returns JSON
failure_url = "https://google.com"  # doesn't return JSON


def test_json_decode_success():
    assert isinstance(get(success_url).json(), dict)


def test_json_decode_failure_catch():
    # test that all exceptions can be caught
    with pytest.raises(json.JSONDecodeError):
        get(failure_url).json()

    with pytest.raises(simplejson.JSONDecodeError):
        get(failure_url).json()

    with pytest.raises(JSONDecodeError):
        get(failure_url).json()

    with pytest.raises(ValueError):
        get(failure_url).json()
