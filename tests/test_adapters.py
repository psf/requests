import pickle
from unittest.mock import MagicMock, patch

import pytest

import requests
import requests.adapters


def test_request_url_trims_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6643."""
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "/v:h" == a.request_url(p, {})


class TestUrllib3UrlopenKwargs:
    """Tests for urllib3_urlopen_kwargs attribute."""

    def test_attribute_exists_and_is_empty_by_default(self) -> None:
        """Test that urllib3_urlopen_kwargs attribute exists and is empty dict."""
        adapter = requests.adapters.HTTPAdapter()
        assert hasattr(adapter, "urllib3_urlopen_kwargs")
        assert adapter.urllib3_urlopen_kwargs == {}
        assert isinstance(adapter.urllib3_urlopen_kwargs, dict)

    def test_custom_kwargs_passed_to_urlopen(self) -> None:
        """Test that custom kwargs are passed through to urllib3's urlopen."""
        adapter = requests.adapters.HTTPAdapter()
        adapter.urllib3_urlopen_kwargs["enforce_content_length"] = False

        # Mock the connection's urlopen method
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.reason = "OK"

        with patch.object(
            adapter, "get_connection_with_tls_context"
        ) as mock_get_conn:
            mock_conn = MagicMock()
            mock_conn.urlopen.return_value = mock_response
            mock_get_conn.return_value = mock_conn

            # Prepare and send a request
            request = requests.Request("GET", "http://example.com").prepare()
            adapter.send(request)

            # Verify urlopen was called with enforce_content_length
            call_kwargs = mock_conn.urlopen.call_args[1]
            assert "enforce_content_length" in call_kwargs
            assert call_kwargs["enforce_content_length"] is False

    def test_kwargs_can_override_defaults(self) -> None:
        """Test that user kwargs can override default urlopen arguments."""
        adapter = requests.adapters.HTTPAdapter()
        adapter.urllib3_urlopen_kwargs["preload_content"] = True
        adapter.urllib3_urlopen_kwargs["decode_content"] = True

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.reason = "OK"

        with patch.object(
            adapter, "get_connection_with_tls_context"
        ) as mock_get_conn:
            mock_conn = MagicMock()
            mock_conn.urlopen.return_value = mock_response
            mock_get_conn.return_value = mock_conn

            request = requests.Request("GET", "http://example.com").prepare()
            adapter.send(request)

            # Verify the overrides were applied
            call_kwargs = mock_conn.urlopen.call_args[1]
            assert call_kwargs["preload_content"] is True
            assert call_kwargs["decode_content"] is True

    def test_pickling_preserves_urllib3_urlopen_kwargs(self) -> None:
        """Test that urllib3_urlopen_kwargs survives pickling."""
        adapter = requests.adapters.HTTPAdapter()
        adapter.urllib3_urlopen_kwargs["enforce_content_length"] = False
        adapter.urllib3_urlopen_kwargs["custom_key"] = "custom_value"

        # Pickle and unpickle
        pickled = pickle.dumps(adapter)
        unpickled_adapter = pickle.loads(pickled)

        # Verify the attribute was preserved
        assert hasattr(unpickled_adapter, "urllib3_urlopen_kwargs")
        assert unpickled_adapter.urllib3_urlopen_kwargs == {
            "enforce_content_length": False,
            "custom_key": "custom_value",
        }

    def test_integration_with_session(self) -> None:
        """Test that custom adapter works with Session."""

        class CustomAdapter(requests.adapters.HTTPAdapter):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.urllib3_urlopen_kwargs["enforce_content_length"] = False

        session = requests.Session()
        adapter = CustomAdapter()

        # Mount for both http and https
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Verify the adapter is installed
        assert isinstance(session.get_adapter("http://example.com"), CustomAdapter)
        assert isinstance(session.get_adapter("https://example.com"), CustomAdapter)

        # Verify the attribute is set
        http_adapter = session.get_adapter("http://example.com")
        https_adapter = session.get_adapter("https://example.com")
        assert http_adapter.urllib3_urlopen_kwargs == {"enforce_content_length": False}
        assert https_adapter.urllib3_urlopen_kwargs == {
            "enforce_content_length": False
        }

    def test_multiple_kwargs_passed_correctly(self) -> None:
        """Test that multiple custom kwargs are all passed correctly."""
        adapter = requests.adapters.HTTPAdapter()
        adapter.urllib3_urlopen_kwargs.update(
            {
                "enforce_content_length": False,
                "custom_arg1": "value1",
                "custom_arg2": 42,
                "custom_arg3": True,
            }
        )

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.reason = "OK"

        with patch.object(
            adapter, "get_connection_with_tls_context"
        ) as mock_get_conn:
            mock_conn = MagicMock()
            mock_conn.urlopen.return_value = mock_response
            mock_get_conn.return_value = mock_conn

            request = requests.Request("GET", "http://example.com").prepare()
            adapter.send(request)

            # Verify all kwargs were passed
            call_kwargs = mock_conn.urlopen.call_args[1]
            assert call_kwargs["enforce_content_length"] is False
            assert call_kwargs["custom_arg1"] == "value1"
            assert call_kwargs["custom_arg2"] == 42
            assert call_kwargs["custom_arg3"] is True

    def test_default_kwargs_still_present(self) -> None:
        """Test that default kwargs are still present when adding custom ones."""
        adapter = requests.adapters.HTTPAdapter()
        adapter.urllib3_urlopen_kwargs["enforce_content_length"] = False

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.reason = "OK"

        with patch.object(
            adapter, "get_connection_with_tls_context"
        ) as mock_get_conn:
            mock_conn = MagicMock()
            mock_conn.urlopen.return_value = mock_response
            mock_get_conn.return_value = mock_conn

            request = requests.Request("GET", "http://example.com").prepare()
            adapter.send(request)

            # Verify default kwargs are still present
            call_kwargs = mock_conn.urlopen.call_args[1]
            assert "method" in call_kwargs
            assert "url" in call_kwargs
            assert "headers" in call_kwargs
            assert "redirect" in call_kwargs
            assert call_kwargs["redirect"] is False
            assert "assert_same_host" in call_kwargs
            assert call_kwargs["assert_same_host"] is False
            assert "retries" in call_kwargs
            assert "timeout" in call_kwargs
