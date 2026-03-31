import requests.adapters


def test_request_url_preserves_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6711.
    
    S3 presigned URLs with keys starting with '/' produce paths like
    '//key_name'. We should preserve leading slashes to avoid breaking signatures.
    """
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(
        method="GET", url="https://bucket.s3.amazonaws.com//key_with_leading_slash.txt"
    ).prepare()
    assert "//key_with_leading_slash.txt" == a.request_url(p, {})
