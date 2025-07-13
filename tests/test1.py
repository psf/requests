import pytest
from requests.auth import HTTPDigestAuth

def test_digest_uri_with_semicolon(monkeypatch):
    # 构造一个带分号的 URL
    url = "http://example.com/path1;param1/part2;param2?foo=bar"
    method = "GET"
    username = "user"
    password = "pass"

    # 构造一个假的 challenge
    chal = {
        "realm": "testrealm",
        "nonce": "abcdef",
        "qop": "auth",
        "algorithm": "MD5",
        "opaque": "opaque-value"
    }

    # 实例化 DigestAuth
    auth = HTTPDigestAuth(username, password)
    auth.init_per_thread_state()
    auth._thread_local.chal = chal
    auth._thread_local.last_nonce = ""  # 强制生成新的 cnonce

    # monkeypatch urlparse 以确保我们测试的就是我们想要的 url
    from requests.auth import urlparse
    assert urlparse(url).path == "/path1;param1/part2"
    assert urlparse(url).params == "param2"

    # 生成 header
    header = auth.build_digest_header(method, url)
    # 检查 uri 字段是否包含分号和参数
    assert 'uri="/path1;param1/part2;param2?foo=bar"' in header

if __name__ == "__main__":
    pytest.main([__file__])
