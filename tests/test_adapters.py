import requests
import requests.adapters


def test_request_url_trims_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6643."""
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "/v:h" == a.request_url(p, {})


def test_build_response_sets_decode_content():
    adapter = requests.adapters.HTTPAdapter()
    req = requests.Request(method="GET", url="http://example.com/").prepare()
    raw_resp = type(
        "RawResponse",
        (),
        {"status": 200, "headers": {}, "reason": "OK", "decode_content": False},
    )()

    response = adapter.build_response(req, raw_resp)

    assert response.raw.decode_content is True
