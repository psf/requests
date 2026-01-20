import requests.adapters


def test_request_url_trims_leading_path_separators():
    """
    Verifies that the request URL correctly trims leading path separators to ensure consistent URL normalization.
    
    This test ensures Requests handles malformed URLs with double slashes at the beginning of the path correctly, maintaining compatibility with HTTP standards and preventing potential issues in URL routing or server-side processing. The behavior aligns with the library's goal of providing reliable, predictable HTTP request handling by normalizing URLs before sending them.
    """
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "/v:h" == a.request_url(p, {})
