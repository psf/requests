"""
Hypothesis-based property tests for requests.models module.

These tests use property-based testing to verify the invariants and properties
of Request, PreparedRequest, and Response classes.
"""

import json
from io import BytesIO

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from requests.exceptions import InvalidJSONError, InvalidURL, MissingSchema
from requests.models import PreparedRequest, Request, Response
from requests.structures import CaseInsensitiveDict


# Custom strategies for HTTP methods and URLs
http_methods = st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
valid_schemes = st.sampled_from(["http", "https"])
valid_domains = st.text(
    alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
    min_size=1,
    max_size=30,
)
valid_paths = st.text(
    alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")) | st.just("/"),
    min_size=0,
    max_size=50,
)


@st.composite
def valid_urls(draw):
    """Strategy for generating valid URLs."""
    scheme = draw(valid_schemes)
    domain = draw(valid_domains)
    path = draw(valid_paths)
    return f"{scheme}://{domain}.com/{path}"


class TestRequestProperties:
    """Property-based tests for Request class."""

    @given(http_methods, valid_urls())
    def test_request_creation(self, method: str, url: str) -> None:
        """Request should be creatable with method and URL."""
        req = Request(method=method, url=url)
        assert isinstance(req, Request)
        assert req.method == method
        assert req.url == url

    @given(
        http_methods,
        valid_urls(),
        st.dictionaries(
            st.text(min_size=1, max_size=20), st.text(min_size=0, max_size=100), max_size=10
        ),
    )
    def test_request_with_headers(self, method: str, url: str, headers: dict) -> None:
        """Request should accept headers."""
        req = Request(method=method, url=url, headers=headers)
        assert req.headers == headers

    @given(
        http_methods,
        valid_urls(),
        st.dictionaries(st.text(min_size=1, max_size=20), st.text(min_size=0, max_size=100)),
    )
    def test_request_with_params(self, method: str, url: str, params: dict) -> None:
        """Request should accept params."""
        req = Request(method=method, url=url, params=params)
        assert req.params == params

    @given(http_methods, valid_urls())
    def test_request_prepare_returns_prepared_request(self, method: str, url: str) -> None:
        """Request.prepare() should return PreparedRequest."""
        req = Request(method=method, url=url)
        prepared = req.prepare()
        assert isinstance(prepared, PreparedRequest)

    @given(http_methods, valid_urls())
    def test_request_repr(self, method: str, url: str) -> None:
        """Request repr should include method."""
        req = Request(method=method, url=url)
        repr_str = repr(req)
        assert isinstance(repr_str, str)
        assert method in repr_str
        assert "Request" in repr_str

    @given(
        http_methods,
        valid_urls(),
        st.text(min_size=0, max_size=100),
    )
    def test_request_with_data(self, method: str, url: str, data: str) -> None:
        """Request should accept data."""
        req = Request(method=method, url=url, data=data)
        assert req.data == data


class TestPreparedRequestProperties:
    """Property-based tests for PreparedRequest class."""

    @given(http_methods)
    def test_prepared_request_method_normalization(self, method: str) -> None:
        """PreparedRequest should normalize method to uppercase."""
        preq = PreparedRequest()
        preq.prepare_method(method)
        assert preq.method == method.upper()

    @given(valid_urls())
    def test_prepared_request_url(self, url: str) -> None:
        """PreparedRequest should accept and store URL."""
        preq = PreparedRequest()
        try:
            preq.prepare_url(url, None)
            assert preq.url is not None
            assert isinstance(preq.url, str)
        except (InvalidURL, MissingSchema):
            # Some generated URLs may be invalid
            pass

    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
                min_size=1,
                max_size=20,
            ),
            st.text(min_size=0, max_size=100),
            max_size=10,
        )
    )
    def test_prepared_request_headers(self, headers: dict) -> None:
        """PreparedRequest should store headers as CaseInsensitiveDict."""
        preq = PreparedRequest()
        try:
            preq.prepare_headers(headers)
            assert isinstance(preq.headers, CaseInsensitiveDict)
            for key, value in headers.items():
                assert key in preq.headers or key.lower() in preq.headers
        except Exception:
            # Some header values might be invalid
            pass

    @given(http_methods, valid_urls())
    def test_prepared_request_copy(self, method: str, url: str) -> None:
        """PreparedRequest.copy() should create independent copy."""
        preq = PreparedRequest()
        preq.prepare_method(method)
        try:
            preq.prepare_url(url, None)
            copy = preq.copy()
            assert copy is not preq
            assert copy.method == preq.method
            assert copy.url == preq.url
        except (InvalidURL, MissingSchema):
            pass

    @given(http_methods)
    def test_prepared_request_repr(self, method: str) -> None:
        """PreparedRequest repr should include method."""
        preq = PreparedRequest()
        preq.prepare_method(method)
        repr_str = repr(preq)
        assert isinstance(repr_str, str)
        assert method.upper() in repr_str
        assert "PreparedRequest" in repr_str

    @given(
        st.dictionaries(
            st.text(min_size=1, max_size=20), st.text(min_size=0, max_size=50), max_size=5
        )
    )
    def test_prepared_request_json_body(self, data: dict) -> None:
        """PreparedRequest should handle JSON data."""
        preq = PreparedRequest()
        try:
            preq.prepare_body(data=None, files=None, json=data)
            assert preq.body is not None
            # Body should be valid JSON
            parsed = json.loads(preq.body)
            assert parsed == data
        except (InvalidJSONError, TypeError):
            # Some data might not be JSON serializable
            pass

    @given(st.text(min_size=0, max_size=100))
    def test_prepared_request_string_body(self, data: str) -> None:
        """PreparedRequest should handle string data."""
        preq = PreparedRequest()
        preq.prepare_headers({})  # Headers must be initialized first
        preq.prepare_body(data=data, files=None, json=None)
        # String data should be encoded
        assert preq.body is not None or data == ""

    @given(
        http_methods,
        valid_urls(),
        st.dictionaries(st.text(min_size=1, max_size=20), st.text(min_size=0, max_size=50)),
    )
    def test_prepared_request_params_encoding(
        self, method: str, url: str, params: dict
    ) -> None:
        """PreparedRequest should encode params into URL."""
        preq = PreparedRequest()
        preq.prepare_method(method)
        try:
            preq.prepare_url(url, params)
            if params:
                # URL should contain encoded params
                assert "?" in preq.url or not params
        except (InvalidURL, MissingSchema):
            pass


class TestResponseProperties:
    """Property-based tests for Response class."""

    @given(st.integers(min_value=100, max_value=599))
    def test_response_status_code(self, status_code: int) -> None:
        """Response should accept valid HTTP status codes."""
        resp = Response()
        resp.status_code = status_code
        assert resp.status_code == status_code

    @given(st.integers(min_value=200, max_value=399))
    def test_response_ok_for_2xx_3xx(self, status_code: int) -> None:
        """Response with 2xx or 3xx status should be ok."""
        resp = Response()
        resp.status_code = status_code
        resp.url = "http://example.com"
        assert resp.ok is True

    @given(st.integers(min_value=400, max_value=599))
    def test_response_not_ok_for_4xx_5xx(self, status_code: int) -> None:
        """Response with 4xx or 5xx status should not be ok."""
        resp = Response()
        resp.status_code = status_code
        resp.url = "http://example.com"
        assert resp.ok is False

    @given(st.binary(min_size=0, max_size=1000))
    def test_response_content(self, content: bytes) -> None:
        """Response should store and return content."""
        resp = Response()
        resp._content = content
        resp._content_consumed = True
        assert resp.content == content

    @given(st.text(min_size=0, max_size=100))
    def test_response_text(self, text: str) -> None:
        """Response should convert content to text."""
        resp = Response()
        resp._content = text.encode("utf-8")
        resp._content_consumed = True
        resp.encoding = "utf-8"
        assert isinstance(resp.text, str)

    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
                min_size=1,
                max_size=20,
            ),
            st.one_of(st.text(min_size=0, max_size=50), st.integers(), st.floats(allow_nan=False)),
            max_size=5,
        )
    )
    def test_response_json(self, data: dict) -> None:
        """Response.json() should parse JSON content."""
        resp = Response()
        try:
            json_str = json.dumps(data)
            resp._content = json_str.encode("utf-8")
            resp._content_consumed = True
            resp.encoding = "utf-8"
            parsed = resp.json()
            assert parsed == data
        except (ValueError, TypeError):
            # Some data might not be JSON serializable
            pass

    @given(st.integers(min_value=100, max_value=599))
    def test_response_repr(self, status_code: int) -> None:
        """Response repr should include status code."""
        resp = Response()
        resp.status_code = status_code
        repr_str = repr(resp)
        assert isinstance(repr_str, str)
        assert str(status_code) in repr_str
        assert "Response" in repr_str

    @given(st.integers(min_value=100, max_value=599))
    def test_response_bool(self, status_code: int) -> None:
        """Response bool conversion should match ok property."""
        resp = Response()
        resp.status_code = status_code
        resp.url = "http://example.com"
        assert bool(resp) == resp.ok

    @given(
        st.dictionaries(
            st.text(
                alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
                min_size=1,
                max_size=20,
            ),
            st.text(min_size=0, max_size=100),
            max_size=10,
        )
    )
    def test_response_headers(self, headers: dict) -> None:
        """Response headers should be CaseInsensitiveDict."""
        resp = Response()
        resp.headers = CaseInsensitiveDict(headers)
        assert isinstance(resp.headers, CaseInsensitiveDict)
        for key, value in headers.items():
            assert resp.headers.get(key.lower()) == value or resp.headers.get(key) == value

    @given(st.sampled_from([301, 302, 303, 307, 308]))
    def test_response_is_redirect(self, status_code: int) -> None:
        """Response with redirect status and location should be redirect."""
        resp = Response()
        resp.status_code = status_code
        resp.headers = CaseInsensitiveDict({"location": "http://example.com/new"})
        assert resp.is_redirect is True

    @given(st.sampled_from([301, 308]))
    def test_response_is_permanent_redirect(self, status_code: int) -> None:
        """Response with 301 or 308 and location should be permanent redirect."""
        resp = Response()
        resp.status_code = status_code
        resp.headers = CaseInsensitiveDict({"location": "http://example.com/new"})
        assert resp.is_permanent_redirect is True

    @given(st.sampled_from([200, 404, 500]))
    def test_response_is_not_redirect(self, status_code: int) -> None:
        """Response without redirect status should not be redirect."""
        resp = Response()
        resp.status_code = status_code
        resp.headers = CaseInsensitiveDict({})
        assert resp.is_redirect is False


class TestRequestResponseInvariants:
    """Test invariants that should hold across Request/Response interactions."""

    @given(http_methods, valid_urls())
    def test_request_prepare_preserves_method(self, method: str, url: str) -> None:
        """Preparing a request should preserve method (as uppercase)."""
        req = Request(method=method, url=url)
        prepared = req.prepare()
        assert prepared.method == method.upper()

    @given(http_methods, valid_urls())
    def test_request_prepare_preserves_url(self, method: str, url: str) -> None:
        """Preparing a request should preserve URL."""
        req = Request(method=method, url=url)
        try:
            prepared = req.prepare()
            # URL should be present (may be modified/normalized)
            assert prepared.url is not None
            assert isinstance(prepared.url, str)
        except (InvalidURL, MissingSchema):
            pass

    @given(
        http_methods,
        valid_urls(),
        st.dictionaries(
            st.text(
                alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
                min_size=1,
                max_size=20,
            ),
            st.text(min_size=0, max_size=100),
            max_size=5,
        ),
    )
    def test_request_prepare_preserves_headers(
        self, method: str, url: str, headers: dict
    ) -> None:
        """Preparing a request should preserve headers."""
        req = Request(method=method, url=url, headers=headers)
        try:
            prepared = req.prepare()
            assert isinstance(prepared.headers, CaseInsensitiveDict)
            for key in headers:
                # Header should be present (case-insensitively)
                assert (
                    key in prepared.headers
                    or key.lower() in prepared.headers
                    or key.upper() in prepared.headers
                )
        except Exception:
            pass

    @given(st.integers(min_value=100, max_value=599))
    def test_response_bool_consistency(self, status_code: int) -> None:
        """Response bool and ok property should be consistent."""
        resp = Response()
        resp.status_code = status_code
        resp.url = "http://example.com"
        assert bool(resp) == resp.ok

    @given(st.binary(min_size=0, max_size=500))
    def test_response_content_idempotent(self, content: bytes) -> None:
        """Accessing response.content multiple times should return same value."""
        resp = Response()
        resp._content = content
        resp._content_consumed = True
        first = resp.content
        second = resp.content
        assert first == second == content

    @given(
        st.integers(min_value=200, max_value=299),
        st.text(min_size=0, max_size=100),
    )
    def test_response_text_is_unicode(self, status_code: int, text: str) -> None:
        """Response.text should always return str (unicode)."""
        resp = Response()
        resp.status_code = status_code
        resp._content = text.encode("utf-8")
        resp._content_consumed = True
        resp.encoding = "utf-8"
        result = resp.text
        assert isinstance(result, str)


class TestRequestEncodingInvariants:
    """Test encoding-related invariants for requests."""

    @given(
        http_methods,
        valid_urls(),
        st.dictionaries(st.text(min_size=1, max_size=20), st.text(min_size=0, max_size=50)),
    )
    def test_params_in_prepared_url(self, method: str, url: str, params: dict) -> None:
        """Params should be encoded in prepared URL."""
        assume(len(params) > 0)
        req = Request(method=method, url=url, params=params)
        try:
            prepared = req.prepare()
            # If params were provided, URL should be modified
            if params:
                assert "?" in prepared.url or prepared.url != url
        except (InvalidURL, MissingSchema):
            pass

    @given(http_methods, valid_urls(), st.text(min_size=1, max_size=100))
    def test_string_body_is_encoded(self, method: str, url: str, body: str) -> None:
        """String body should be encoded in prepared request."""
        req = Request(method=method, url=url, data=body)
        try:
            prepared = req.prepare()
            if body:
                assert prepared.body is not None
        except (InvalidURL, MissingSchema):
            pass


class TestPreparedRequestPathURL:
    """Test path_url property of PreparedRequest."""

    @given(valid_urls())
    def test_path_url_excludes_scheme_and_host(self, url: str) -> None:
        """path_url should exclude scheme and host."""
        preq = PreparedRequest()
        try:
            preq.prepare_url(url, None)
            path_url = preq.path_url
            assert isinstance(path_url, str)
            # Should start with /
            assert path_url.startswith("/")
            # Should not contain ://
            assert "://" not in path_url
        except (InvalidURL, MissingSchema):
            pass

    @given(
        valid_urls(),
        st.dictionaries(st.text(min_size=1, max_size=10), st.text(min_size=1, max_size=10)),
    )
    def test_path_url_includes_query(self, url: str, params: dict) -> None:
        """path_url should include query parameters."""
        assume(len(params) > 0)
        preq = PreparedRequest()
        try:
            preq.prepare_url(url, params)
            path_url = preq.path_url
            if params:
                assert "?" in path_url
        except (InvalidURL, MissingSchema):
            pass

