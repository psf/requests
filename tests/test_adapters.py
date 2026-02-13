import ssl
from unittest.mock import MagicMock

import pytest
import pytest_httpbin.certs

import requests.adapters


def test_request_url_trims_leading_path_separators():
    """See also https://github.com/psf/requests/issues/6643."""
    a = requests.adapters.HTTPAdapter()
    p = requests.Request(method="GET", url="http://127.0.0.1:10000//v:h").prepare()
    assert "/v:h" == a.request_url(p, {})


def test_adapter_ssl_context(httpbin_secure):
    # We can't verify that SSL actually works on localhost, but we can check
    # if the ssl context gets actually used.
    ssl_context = ssl.create_default_context(cafile=pytest_httpbin.certs.where())
    ssl_mock = MagicMock(spec=ssl.SSLContext, wraps=ssl_context)

    class SSLContextAdapter(requests.adapters.HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            kwargs["ssl_context"] = ssl_mock
            return super().init_poolmanager(*args, **kwargs)

        def cert_verify(self, *_args, **_kwargs) -> None:
            # Override HTTPAdapter method, it tries to load certs from disk otherwise
            pass

    with requests.Session() as session:
        # Disable environment configuration, it overrides the passed SSLContext
        session.trust_env = False

        session.mount("https://", SSLContextAdapter())

        res = session.get(httpbin_secure())
        res.raise_for_status()

    # Check that the SSLContext was actually used
    ssl_mock.wrap_socket.assert_called()

    # Check it wasn't modified by requests or urllib3
    ssl_mock.load_verify_locations.assert_not_called()
    ssl_mock.load_default_certs.assert_not_called()
    ssl_mock.load_cert_chain.assert_not_called()
