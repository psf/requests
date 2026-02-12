import pytest
from urllib3.util import Timeout as TimeoutSauce

import requests.adapters


def test_request_url_trims_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6643."""
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "/v:h" == a.request_url(p, {})


class TestPrepareTimeout:
    """Tests for timeout processing in HTTPAdapter."""

    def test_prepare_timeout_with_valid_tuple(self):
        """Test that valid timeout tuples are converted to TimeoutSauce."""
        adapter = requests.adapters.HTTPAdapter()
        result = adapter._prepare_timeout((5.0, 10.0))
        assert isinstance(result, TimeoutSauce)
        assert result.connect_timeout == 5.0
        assert result.read_timeout == 10.0

    def test_prepare_timeout_with_none_values_in_tuple(self):
        """Test that tuples with None values are handled correctly."""
        adapter = requests.adapters.HTTPAdapter()
        result = adapter._prepare_timeout((5.0, None))
        assert isinstance(result, TimeoutSauce)
        assert result.connect_timeout == 5.0
        assert result.read_timeout is None

    def test_prepare_timeout_with_float(self):
        """Test that float timeouts are converted to TimeoutSauce."""
        adapter = requests.adapters.HTTPAdapter()
        result = adapter._prepare_timeout(10.0)
        assert isinstance(result, TimeoutSauce)
        assert result.connect_timeout == 10.0
        assert result.read_timeout == 10.0

    def test_prepare_timeout_with_none(self):
        """Test that None timeout is converted to TimeoutSauce."""
        adapter = requests.adapters.HTTPAdapter()
        result = adapter._prepare_timeout(None)
        assert isinstance(result, TimeoutSauce)
        assert result.connect_timeout is None
        assert result.read_timeout is None

    def test_prepare_timeout_with_timeout_sauce(self):
        """Test that TimeoutSauce objects are returned unchanged."""
        adapter = requests.adapters.HTTPAdapter()
        timeout_sauce = TimeoutSauce(connect=3.0, read=5.0)
        result = adapter._prepare_timeout(timeout_sauce)
        assert result is timeout_sauce

    def test_prepare_timeout_with_too_many_values(self):
        """Test that tuples with too many values raise ValueError with chaining."""
        adapter = requests.adapters.HTTPAdapter()
        with pytest.raises(ValueError) as exc_info:
            adapter._prepare_timeout((1, 2, 3))

        # Check that the error message is correct
        assert "Invalid timeout" in str(exc_info.value)
        assert "(connect, read)" in str(exc_info.value)

        # Check that exception chaining is preserved
        assert exc_info.value.__cause__ is not None
        assert isinstance(exc_info.value.__cause__, ValueError)
        assert "too many values to unpack" in str(exc_info.value.__cause__)

    def test_prepare_timeout_with_too_few_values(self):
        """Test that tuples with too few values raise ValueError with chaining."""
        adapter = requests.adapters.HTTPAdapter()
        with pytest.raises(ValueError) as exc_info:
            adapter._prepare_timeout((1,))

        # Check that the error message is correct
        assert "Invalid timeout" in str(exc_info.value)
        assert "(connect, read)" in str(exc_info.value)

        # Check that exception chaining is preserved
        assert exc_info.value.__cause__ is not None
        assert isinstance(exc_info.value.__cause__, ValueError)
        assert "not enough values to unpack" in str(exc_info.value.__cause__)

    def test_prepare_timeout_with_empty_tuple(self):
        """Test that empty tuples raise ValueError with chaining."""
        adapter = requests.adapters.HTTPAdapter()
        with pytest.raises(ValueError) as exc_info:
            adapter._prepare_timeout(())

        # Check that the error message is correct
        assert "Invalid timeout" in str(exc_info.value)

        # Check that exception chaining is preserved
        assert exc_info.value.__cause__ is not None
