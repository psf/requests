import requests.adapters


def test_request_url_trims_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6643."""
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "/v:h" == a.request_url(p, {})


def test_http_adapter_send():
    """Test the send method of HTTPAdapter."""
    adapter = requests.adapters.HTTPAdapter()
    request = requests.Request(method="GET", url="http://httpbin.org/get").prepare()
    response = adapter.send(request)
    assert response.status_code == 200
    assert response.request == request
    assert response.connection == adapter


def test_http_adapter_cert_verify():
    """Test the cert_verify method of HTTPAdapter."""
    adapter = requests.adapters.HTTPAdapter()
    conn = adapter.get_connection("https://httpbin.org")
    adapter.cert_verify(conn, "https://httpbin.org", True, None)
    assert conn.cert_reqs == "CERT_REQUIRED"
    assert conn.ca_certs is not None
    assert conn.ca_cert_dir is None
