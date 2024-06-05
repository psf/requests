import pytest

import requests


@pytest.mark.parametrize(
    "method", ("get", "head", "options", "delete", "put", "post", "patch")
)
def test_highlevel_api(httpbin, method):
    function = getattr(requests, method)
    response = function(httpbin("/status/200"))
    assert response.status_code == 200
