import pytest

# from requests.auth import HTTPDigestAuth
from src.requests.auth import HTTPDigestAuth


class TestDigestAuth:
    def _build_a_digest_auth(self, user, password):
        auth = HTTPDigestAuth(user, password)
        auth.init_per_thread_state()
        auth._thread_local.chal["realm"] = "eggs"
        auth._thread_local.chal["nonce"] = "chips"
        return auth.build_digest_header("GET", "https://www.example.com/")

    @pytest.mark.parametrize(
        "username, password",
        (
            ("spam", "ham"),
            ("имя", "пароль"),
        ),
    )
    def test_digestauth_encode_consistency(self, username, password):
        auth = username, password
        str_auth = self._build_a_digest_auth(*auth)
        bauth = username.encode("utf-8"), password.encode("utf-8")
        bin_auth = self._build_a_digest_auth(*bauth)
        assert str_auth == bin_auth
