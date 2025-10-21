from unittest import mock

import pytest
from urllib3.exceptions import HTTPError as _HTTPError

import requests.adapters
from requests.exceptions import RequestException


def test_request_url_trims_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6643."""
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "/v:h" == a.request_url(p, {})


def test_unknown_httperror_wrapped_in_requestexception():
    """Test that unknown urllib3 HTTPError types are wrapped in RequestException.
    
    When urllib3 raises an HTTPError that isn't explicitly
    handled (not SSLError, ReadTimeoutError, or InvalidHeader), it should be
    wrapped in RequestException rather than propagating as-is.
    """
    adapter = requests.adapters.HTTPAdapter()
    request = requests.Request(method="GET", url="http://example.com").prepare()
    
    # Create a generic HTTPError that doesn't match any specific handled types
    generic_http_error = _HTTPError("Unknown HTTP error from urllib3")
    
    # Mock the connection to raise our generic HTTPError
    with mock.patch.object(
        adapter, 'get_connection_with_tls_context'
    ) as mock_get_conn:
        mock_conn = mock.MagicMock()
        mock_conn.urlopen.side_effect = generic_http_error
        mock_get_conn.return_value = mock_conn
        
        # The exception should be catchable as RequestException
        with pytest.raises(RequestException) as exc_info:
            adapter.send(request)
        
        # Verify it wraps the original error
        assert exc_info.value.request == request
        # Verify exception chaining
        assert exc_info.value.__cause__ == generic_http_error
