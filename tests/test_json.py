import pytest
import simplejson
import json

from requests import get, JSONDecodeError

success_url = "https://httpbin.org/get"
failure_url = "https://google.com"


def test_json_decode_success():
    assert isinstance(get(success_url).json(), dict)


def test_json_decode_failure_normal_catch():
    with pytest.raises(json.JSONDecodeError):
        get(failure_url).json()


def test_json_decode_failure_simplejson_catch():
    with pytest.raises(simplejson.JSONDecodeError):
        get(failure_url).json()
