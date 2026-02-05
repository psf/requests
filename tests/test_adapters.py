import pytest
import requests.adapters
from requests.models import PreparedRequest


def test_request_url_trims_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6643."""
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "/v:h" == a.request_url(p, {})


def test_request_url_with_none_url():
    """Test that request_url() handles None url gracefully.
    
    PreparedRequest.__init__() initializes self.url = None,
    so request_url() should handle this case defensively.
    """
    a = requests.adapters.HTTPAdapter()
    p = PreparedRequest()
    # p.url is None by default
    assert p.url is None
    
    # This should not crash - it should handle None gracefully
    result = a.request_url(p, {})
    # With None url, path_url will be "/" by default
    assert result == "/"


def test_request_url_with_none_url_and_proxy():
    """Test that request_url() handles None url with proxy gracefully.
    
    """
    a = requests.adapters.HTTPAdapter()
    p = PreparedRequest()
    p.url = None
    
    proxies = {"http": "http://proxy.example.com:8080"}
    
    # This should not crash
    result = a.request_url(p, proxies)
    assert result == "/"


def test_send_with_none_headers():
    """Test that send() handles None headers gracefully.
    
    PreparedRequest.__init__() initializes self.headers = None,
    so send() should handle this case defensively when checking
    for 'Content-Length' in headers.
    """
    a = requests.adapters.HTTPAdapter()
    p = PreparedRequest()
    p.method = "POST"
    p.url = "http://httpbin.org/post"
    p.headers = None  # Explicitly set to None
    p.body = b"test data"  # Non-None body triggers the headers check
    
    # This should not raise TypeError from 'in None' check
    # It may raise other exceptions (like connection errors), but not TypeError
    try:
        a.send(p)
    except TypeError as e:
        # If we get a TypeError, there is an issue
        if "argument of type 'NoneType' is not iterable" in str(e):
            pytest.fail(f"Bug still exists! Got TypeError from 'in None' check: {e}")
        else:
            # Some other TypeError, re-raise
            raise
    except Exception:
        # Any other exception is expected (connection errors, etc.)
        # The important thing is we didn't get TypeError from the None check
        pass


def test_urllib3_request_context_with_none_url():
    """Test that _urllib3_request_context() handles None url gracefully.
    
    """
    from requests.adapters import _urllib3_request_context
    
    a = requests.adapters.HTTPAdapter()
    p = PreparedRequest()
    p.url = None  # Explicitly None
    
    # This should not raise AttributeError/TypeError from parsing None
    # It should parse "" instead, which results in empty scheme/host/port
    try:
        host_params, pool_kwargs = _urllib3_request_context(p, True, None, a.poolmanager)
        # If we get here, it handled None gracefully
        # Verify we got empty/default values
        assert host_params["scheme"] == ""
        assert host_params["host"] is None
        assert host_params["port"] is None
    except (AttributeError, TypeError) as e:
        # If we get AttributeError or TypeError, there is an issue
        pytest.fail(f"Bug still exists! Got {type(e).__name__} from None dereference: {e}")
    except Exception:
        # Other exceptions are OK - the important thing is we didn't crash on None
        pass
