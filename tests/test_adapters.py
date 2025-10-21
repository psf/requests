from unittest.mock import Mock, patch

import pytest
from urllib3.exceptions import (
    ClosedPoolError,
    ConnectTimeoutError,
    LocationValueError,
    MaxRetryError,
    NewConnectionError,
    ProtocolError,
    ReadTimeoutError,
    ResponseError,
)
from urllib3.exceptions import HTTPError as _HTTPError
from urllib3.exceptions import InvalidHeader as _InvalidHeader
from urllib3.exceptions import ProxyError as _ProxyError
from urllib3.exceptions import SSLError as _SSLError

import requests.adapters
from requests.exceptions import (
    ConnectionError,
    ConnectTimeout,
    InvalidHeader,
    InvalidURL,
    ProxyError,
    ReadTimeout,
    RetryError,
    SSLError,
)


def test_request_url_trims_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6643."""
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "/v:h" == a.request_url(p, {})


class TestExceptionChaining:
    """Test that exception chains are preserved using the 'from' clause."""

    def test_get_connection_with_tls_context_value_error_chain(self):
        """Test ValueError -> InvalidURL preserves exception chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"

        original_error = ValueError("Invalid pool key attributes")

        with patch.object(
            adapter, "build_connection_pool_key_attributes", side_effect=original_error
        ):
            with pytest.raises(InvalidURL) as exc_info:
                adapter.get_connection_with_tls_context(request, verify=True)

            # Verify the exception chain is preserved
            assert exc_info.value.__cause__ is original_error
            assert isinstance(exc_info.value.__cause__, ValueError)

    def test_send_location_value_error_chain(self):
        """Test LocationValueError -> InvalidURL preserves exception chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"

        original_error = LocationValueError("Invalid location")

        with patch.object(
            adapter, "get_connection_with_tls_context", side_effect=original_error
        ):
            with pytest.raises(InvalidURL) as exc_info:
                adapter.send(request)

            # Verify the exception chain is preserved
            assert exc_info.value.__cause__ is original_error
            assert isinstance(exc_info.value.__cause__, LocationValueError)

    def test_send_protocol_error_chain(self):
        """Test ProtocolError -> ConnectionError preserves exception chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        original_error = ProtocolError("Protocol error occurred")

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(ConnectionError) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, ProtocolError)

    def test_send_os_error_chain(self):
        """Test OSError -> ConnectionError preserves exception chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        original_error = OSError("OS error occurred")

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(ConnectionError) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, OSError)

    def test_send_max_retry_error_connect_timeout_chain(self):
        """Test MaxRetryError (ConnectTimeoutError) -> ConnectTimeout preserves chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        timeout_error = ConnectTimeoutError("Connection timeout")
        original_error = MaxRetryError(
            pool=Mock(), url="http://example.com", reason=timeout_error
        )

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(ConnectTimeout) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, MaxRetryError)

    def test_send_max_retry_error_response_error_chain(self):
        """Test MaxRetryError (ResponseError) -> RetryError preserves chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        response_error = ResponseError("Response error")
        original_error = MaxRetryError(
            pool=Mock(), url="http://example.com", reason=response_error
        )

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(RetryError) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, MaxRetryError)

    def test_send_max_retry_error_proxy_error_chain(self):
        """Test MaxRetryError (_ProxyError) -> ProxyError preserves chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        proxy_error = _ProxyError("http://proxy.example.com", Exception("Proxy error"))
        original_error = MaxRetryError(
            pool=Mock(), url="http://example.com", reason=proxy_error
        )

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(ProxyError) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, MaxRetryError)

    def test_send_max_retry_error_ssl_error_chain(self):
        """Test MaxRetryError (_SSLError) -> SSLError preserves chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        ssl_error = _SSLError("SSL error")
        original_error = MaxRetryError(
            pool=Mock(), url="http://example.com", reason=ssl_error
        )

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(SSLError) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, MaxRetryError)

    def test_send_max_retry_error_generic_chain(self):
        """Test MaxRetryError (generic) -> ConnectionError preserves chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        original_error = MaxRetryError(
            pool=Mock(), url="http://example.com", reason=Exception("Generic error")
        )

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(ConnectionError) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, MaxRetryError)

    def test_send_closed_pool_error_chain(self):
        """Test ClosedPoolError -> ConnectionError preserves chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        original_error = ClosedPoolError(pool=Mock(), message="Pool closed")

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(ConnectionError) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, ClosedPoolError)

    def test_send_proxy_error_chain(self):
        """Test _ProxyError -> ProxyError preserves chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        original_error = _ProxyError("http://proxy.example.com", Exception("Proxy error"))

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(ProxyError) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, _ProxyError)

    def test_send_ssl_error_chain(self):
        """Test _SSLError -> SSLError preserves chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        original_error = _SSLError("SSL error")

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(SSLError) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, _SSLError)

    def test_send_read_timeout_error_chain(self):
        """Test ReadTimeoutError -> ReadTimeout preserves chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        original_error = ReadTimeoutError(pool=Mock(), url="/", message="Timeout")

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(ReadTimeout) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, ReadTimeoutError)

    def test_send_invalid_header_chain(self):
        """Test _InvalidHeader -> InvalidHeader preserves chain."""
        adapter = requests.adapters.HTTPAdapter()
        request = Mock()
        request.url = "http://example.com"
        request.body = None
        request.headers = {}

        original_error = _InvalidHeader("Invalid header")

        with patch.object(adapter, "get_connection_with_tls_context"):
            with patch.object(adapter, "cert_verify"):
                with patch.object(adapter, "request_url", return_value="/"):
                    with patch.object(adapter, "add_headers"):
                        conn = Mock()
                        conn.urlopen.side_effect = original_error
                        adapter.get_connection_with_tls_context = Mock(
                            return_value=conn
                        )

                        with pytest.raises(InvalidHeader) as exc_info:
                            adapter.send(request)

                        # Verify the exception chain is preserved
                        assert exc_info.value.__cause__ is original_error
                        assert isinstance(exc_info.value.__cause__, _InvalidHeader)
