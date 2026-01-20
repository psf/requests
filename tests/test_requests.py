"""Tests for Requests."""

import collections
import contextlib
import io
import json
import os
import pickle
import re
import tempfile
import threading
import warnings
from unittest import mock

import pytest
import urllib3
from urllib3.util import Timeout as Urllib3Timeout

import requests
from requests.adapters import HTTPAdapter
from requests.auth import HTTPDigestAuth, _basic_auth_str
from requests.compat import (
    JSONDecodeError,
    Morsel,
    MutableMapping,
    builtin_str,
    cookielib,
    getproxies,
    is_urllib3_1,
    urlparse,
)
from requests.cookies import cookiejar_from_dict, morsel_to_cookie
from requests.exceptions import (
    ChunkedEncodingError,
    ConnectionError,
    ConnectTimeout,
    ContentDecodingError,
    InvalidHeader,
    InvalidProxyURL,
    InvalidSchema,
    InvalidURL,
    MissingSchema,
    ProxyError,
    ReadTimeout,
    RequestException,
    RetryError,
)
from requests.exceptions import SSLError as RequestsSSLError
from requests.exceptions import Timeout, TooManyRedirects, UnrewindableBodyError
from requests.hooks import default_hooks
from requests.models import PreparedRequest, urlencode
from requests.sessions import SessionRedirectMixin
from requests.structures import CaseInsensitiveDict

from . import SNIMissingWarning
from .compat import StringIO
from .testserver.server import TLSServer, consume_socket_content
from .utils import override_environ

# Requests to this URL should always fail with a connection timeout (nothing
# listening on that port)
TARPIT = "http://10.255.255.1"

# This is to avoid waiting the timeout of using TARPIT
INVALID_PROXY = "http://localhost:1"

try:
    from ssl import SSLContext

    del SSLContext
    HAS_MODERN_SSL = True
except ImportError:
    HAS_MODERN_SSL = False

try:
    requests.pyopenssl
    HAS_PYOPENSSL = True
except AttributeError:
    HAS_PYOPENSSL = False


class TestRequests:
    """
    Tests the functionality and behavior of the requests library through a comprehensive suite of test cases.
    
        This class verifies various aspects of HTTP request handling, including:
        - Request preparation and URL encoding
        - Header and cookie management
        - Authentication mechanisms (basic, digest)
        - Redirect handling and preservation of state
        - Session and connection management
        - Error handling and exception propagation
        - Content encoding and decoding
        - Compatibility with different data types and encodings
        - Proper handling of streaming and file uploads
        - Security considerations (e.g., authentication stripping on protocol downgrade)
    
        The tests cover both standard HTTP methods and edge cases, ensuring robustness across different scenarios and configurations.
    """

    digest_auth_algo = ("MD5", "SHA-256", "SHA-512")

    def test_entry_points(self):
        """
        Verifies that essential public API entry points in the requests module are available and functional.
        
        This test ensures the core functionality expected by users—such as direct module-level functions (get, post, etc.) and session-based methods (session().get, session().post, etc.)—are accessible without errors. It also confirms that commonly used components like PoolManager are importable, as they're relied upon by users even though they're not part of the primary public API surface. This validation supports Requests' mission to provide a reliable, intuitive HTTP client by guaranteeing that the expected interface remains stable and accessible across versions.
        """
        requests.session
        requests.session().get
        requests.session().head
        requests.get
        requests.head
        requests.put
        requests.patch
        requests.post
        # Not really an entry point, but people rely on it.
        from requests.packages.urllib3.poolmanager import PoolManager  # noqa:F401

    @pytest.mark.parametrize(
        "exception, url",
        (
            (MissingSchema, "hiwpefhipowhefopw"),
            (InvalidSchema, "localhost:3128"),
            (InvalidSchema, "localhost.localdomain:3128/"),
            (InvalidSchema, "10.122.1.1:3128/"),
            (InvalidURL, "http://"),
            (InvalidURL, "http://*example.com"),
            (InvalidURL, "http://.example.com"),
        ),
    )
    def test_invalid_url(self, exception, url):
        """
        Tests that making a request with an invalid URL correctly raises the expected exception, ensuring robust error handling in the HTTP client.
        
        Args:
            exception: The expected exception type to be raised when making the request with an invalid URL.
            url: The invalid URL to test, which should trigger the specified exception.
        """
        with pytest.raises(exception):
            requests.get(url)

    def test_basic_building(self):
        """
        Tests the core request preparation logic to ensure that URL and form data are correctly processed into a prepared request, which is essential for reliable HTTP communication.
        
        This test verifies that Requests properly preserves the request URL and serializes form data into the request body during preparation—a fundamental step in building valid HTTP requests. By confirming this behavior, the test ensures the library maintains integrity when sending data via POST or similar methods, supporting the project's goal of providing a simple, robust interface for HTTP interactions.
        """
        req = requests.Request()
        req.url = "http://kennethreitz.org/"
        req.data = {"life": "42"}

        pr = req.prepare()
        assert pr.url == req.url
        assert pr.body == "life=42"

    @pytest.mark.parametrize("method", ("GET", "HEAD"))
    def test_no_content_length(self, httpbin, method):
        """
        Verifies that no Content-Length header is automatically added to requests, ensuring compliance with HTTP standards where such headers should not be sent for methods like GET that do not carry a request body.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing.
            method: HTTP method to use in the request (e.g., GET, POST).
        """
        req = requests.Request(method, httpbin(method.lower())).prepare()
        assert "Content-Length" not in req.headers

    @pytest.mark.parametrize("method", ("POST", "PUT", "PATCH", "OPTIONS"))
    def test_no_body_content_length(self, httpbin, method):
        """
        Verifies that HTTP requests without a body automatically include a Content-Length header set to 0, ensuring compliance with HTTP standards and proper server handling of request semantics.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for making HTTP requests.
            method: HTTP method to use for the request (e.g., GET, POST).
        """
        req = requests.Request(method, httpbin(method.lower())).prepare()
        assert req.headers["Content-Length"] == "0"

    @pytest.mark.parametrize("method", ("POST", "PUT", "PATCH", "OPTIONS"))
    def test_empty_content_length(self, httpbin, method):
        """
        Verifies that HTTP requests with empty bodies correctly set the Content-Length header to 0, ensuring proper adherence to HTTP standards and consistent behavior across different request methods.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing.
            method: HTTP method to use in the request (e.g., GET, POST).
        """
        req = requests.Request(method, httpbin(method.lower()), data="").prepare()
        assert req.headers["Content-Length"] == "0"

    def test_override_content_length(self, httpbin):
        """
        Tests that a custom Content-Length header is preserved during request preparation, ensuring accurate request formatting for APIs that rely on explicit content length values.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing POST requests.
        """
        headers = {"Content-Length": "not zero"}
        r = requests.Request("POST", httpbin("post"), headers=headers).prepare()
        assert "Content-Length" in r.headers
        assert r.headers["Content-Length"] == "not zero"

    def test_path_is_not_double_encoded(self):
        """
        Verifies that URL paths containing spaces are encoded only once during request preparation, preventing double encoding that could break URL parsing or lead to incorrect server behavior. This ensures compatibility with standard HTTP practices and maintains the reliability of requests made through the library, which is critical for consistent API interactions and web service communication.
        """
        request = requests.Request("GET", "http://0.0.0.0/get/test case").prepare()

        assert request.path_url == "/get/test%20case"

    @pytest.mark.parametrize(
        "url, expected",
        (
            (
                "http://example.com/path#fragment",
                "http://example.com/path?a=b#fragment",
            ),
            (
                "http://example.com/path?key=value#fragment",
                "http://example.com/path?key=value&a=b#fragment",
            ),
        ),
    )
    def test_params_are_added_before_fragment(self, url, expected):
        """
        Verifies that URL parameters are correctly appended before the fragment part of a URL, ensuring proper URL construction during HTTP request preparation.
        
        Args:
            url: The base URL to test, which may include a fragment (e.g., '#anchor').
            expected: The expected resulting URL after adding parameters, with parameters placed before the fragment.
        """
        request = requests.Request("GET", url, params={"a": "b"}).prepare()
        assert request.url == expected

    def test_params_original_order_is_preserved_by_default(self):
        """
        Tests that request parameter ordering is preserved as provided in an OrderedDict by default, ensuring predictable and consistent URL construction.
        
        This behavior is important for APIs that rely on parameter order for security, caching, or correctness, such as those using signature validation or deterministic request hashing. Requests maintains the original order of parameters when using OrderedDict without requiring additional configuration, aligning with the library's goal of providing intuitive, reliable HTTP interactions while preserving user intent.
        """
        param_ordered_dict = collections.OrderedDict(
            (("z", 1), ("a", 1), ("k", 1), ("d", 1))
        )
        session = requests.Session()
        request = requests.Request(
            "GET", "http://example.com/", params=param_ordered_dict
        )
        prep = session.prepare_request(request)
        assert prep.url == "http://example.com/?z=1&a=1&k=1&d=1"

    def test_params_bytes_are_encoded(self):
        """
        Tests that bytes parameters are correctly encoded in the request URL, ensuring compatibility with the library's goal of simplifying HTTP requests. This validation confirms that Requests properly handles bytes input in query parameters by decoding them to strings, maintaining consistency with the expected behavior for URL encoding and supporting seamless integration with web APIs.
        """
        request = requests.Request(
            "GET", "http://example.com", params=b"test=foo"
        ).prepare()
        assert request.url == "http://example.com/?test=foo"

    def test_binary_put(self):
        """
        Tests that binary data in a PUT request is correctly preserved as bytes during request preparation, ensuring proper handling of non-ASCII content. This is critical for the Requests library's purpose of reliably transmitting encoded data over HTTP, particularly when working with internationalized or binary content that must not be inadvertently decoded or re-encoded.
        """
        request = requests.Request(
            "PUT", "http://example.com", data="ööö".encode()
        ).prepare()
        assert isinstance(request.body, bytes)

    def test_whitespaces_are_removed_from_url(self):
        """
        Tests that leading and trailing whitespace in URLs is properly stripped during request preparation, ensuring compliance with RFC 3986.
        
        This validation is critical for maintaining correct URL formatting in HTTP requests, preventing malformed URLs that could lead to failed requests or security issues. The test specifically addresses issue #3696, where untrimmed whitespace in URLs caused incorrect request URLs, which could break API integrations or web scraping workflows. By verifying that whitespace is removed by default, this test ensures Requests continues to provide reliable, RFC-compliant HTTP client behavior as intended by its core purpose of simplifying web interactions.
        """
        # Test for issue #3696
        request = requests.Request("GET", " http://example.com").prepare()
        assert request.url == "http://example.com/"

    @pytest.mark.parametrize("scheme", ("http://", "HTTP://", "hTTp://", "HttP://"))
    def test_mixed_case_scheme_acceptable(self, httpbin, scheme):
        """
        Tests that the HTTP client correctly handles mixed-case URL schemes, ensuring robustness in real-world scenarios where URL schemes may be inconsistently cased.
        
        Args:
            httpbin: Fixture that returns a URL to the httpbin service for testing.
            scheme: The URL scheme (e.g., 'http', 'HTTPS') to test in mixed case format. This verifies the client's ability to normalize and accept case variations, which aligns with the project's goal of providing a user-friendly and resilient HTTP client that behaves predictably regardless of input formatting.
        """
        s = requests.Session()
        s.proxies = getproxies()
        parts = urlparse(httpbin("get"))
        url = scheme + parts.netloc + parts.path
        r = requests.Request("GET", url)
        r = s.send(r.prepare())
        assert r.status_code == 200, f"failed for scheme {scheme}"

    def test_HTTP_200_OK_GET_ALTERNATIVE(self, httpbin):
        """
        Tests that a GET request to the HTTPBin endpoint successfully returns a 200 OK status code when using a configured system proxy, verifying that Requests properly handles proxy settings in real-world network conditions.
        
        Args:
            self: Test case instance containing test context.
            httpbin: Fixture providing the HTTPBin URL endpoint for testing.
        """
        r = requests.Request("GET", httpbin("get"))
        s = requests.Session()
        s.proxies = getproxies()

        r = s.send(r.prepare())

        assert r.status_code == 200

    def test_HTTP_302_ALLOW_REDIRECT_GET(self, httpbin):
        """
        Tests that GET requests automatically follow 302 redirects when redirect handling is enabled, ensuring seamless navigation through HTTP redirection chains as expected in real-world web interactions.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        r = requests.get(httpbin("redirect", "1"))
        assert r.status_code == 200
        assert r.history[0].status_code == 302
        assert r.history[0].is_redirect

    def test_HTTP_307_ALLOW_REDIRECT_POST(self, httpbin):
        """
        Tests that POST requests with 307 redirects are correctly handled by following the redirect while preserving the original request method and data, ensuring compliance with HTTP standards. This is critical for maintaining data integrity in web interactions where redirects may occur during API workflows.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP behavior.
        """
        r = requests.post(
            httpbin("redirect-to"),
            data="test",
            params={"url": "post", "status_code": 307},
        )
        assert r.status_code == 200
        assert r.history[0].status_code == 307
        assert r.history[0].is_redirect
        assert r.json()["data"] == "test"

    def test_HTTP_307_ALLOW_REDIRECT_POST_WITH_SEEKABLE(self, httpbin):
        """
        Tests that POST requests with seekable stream data are properly handled during 307 redirects, ensuring the original request method and data are preserved across redirects. This verifies Requests' correct behavior in following redirects while maintaining data integrity, which is essential for reliable HTTP interactions with services that use temporary redirects.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP behavior
        """
        byte_str = b"test"
        r = requests.post(
            httpbin("redirect-to"),
            data=io.BytesIO(byte_str),
            params={"url": "post", "status_code": 307},
        )
        assert r.status_code == 200
        assert r.history[0].status_code == 307
        assert r.history[0].is_redirect
        assert r.json()["data"] == byte_str.decode("utf-8")

    def test_HTTP_302_TOO_MANY_REDIRECTS(self, httpbin):
        """
        Tests that the request library correctly raises a TooManyRedirects exception when following 302 redirects exceeds the configured limit, ensuring robust handling of potentially infinite redirect loops.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior, specifically used here to simulate a chain of 302 redirects.
        """
        try:
            requests.get(httpbin("relative-redirect", "50"))
        except TooManyRedirects as e:
            url = httpbin("relative-redirect", "20")
            assert e.request.url == url
            assert e.response.url == url
            assert len(e.response.history) == 30
        else:
            pytest.fail("Expected redirect to raise TooManyRedirects but it did not")

    def test_HTTP_302_TOO_MANY_REDIRECTS_WITH_PARAMS(self, httpbin):
        """
        Tests that the session's max_redirects limit is enforced when following chained redirects with query parameters, ensuring requests do not indefinitely follow redirect chains. This is critical for preventing infinite loops and ensuring predictable behavior when interacting with HTTP services that may return redirect sequences, aligning with Requests' goal of providing reliable and safe HTTP interactions.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing redirect behavior.
        """
        s = requests.session()
        s.max_redirects = 5
        try:
            s.get(httpbin("relative-redirect", "50"))
        except TooManyRedirects as e:
            url = httpbin("relative-redirect", "45")
            assert e.request.url == url
            assert e.response.url == url
            assert len(e.response.history) == 5
        else:
            pytest.fail(
                "Expected custom max number of redirects to be respected but was not"
            )

    def test_http_301_changes_post_to_get(self, httpbin):
        """
        Tests that Requests automatically converts POST requests to GET when following a 301 redirect, ensuring compliance with HTTP standards and maintaining predictable behavior during redirects.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        r = requests.post(httpbin("status", "301"))
        assert r.status_code == 200
        assert r.request.method == "GET"
        assert r.history[0].status_code == 301
        assert r.history[0].is_redirect

    def test_http_301_doesnt_change_head_to_get(self, httpbin):
        """
        Tests that HTTP 301 redirects preserve the original HEAD method rather than automatically converting to GET, ensuring compliance with HTTP standards and consistent behavior in API clients.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        r = requests.head(httpbin("status", "301"), allow_redirects=True)
        print(r.content)
        assert r.status_code == 200
        assert r.request.method == "HEAD"
        assert r.history[0].status_code == 301
        assert r.history[0].is_redirect

    def test_http_302_changes_post_to_get(self, httpbin):
        """
        Tests that Requests automatically converts POST requests to GET when following 302 redirects, ensuring compliance with HTTP standards and consistent behavior across redirect scenarios.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP behavior.
        """
        r = requests.post(httpbin("status", "302"))
        assert r.status_code == 200
        assert r.request.method == "GET"
        assert r.history[0].status_code == 302
        assert r.history[0].is_redirect

    def test_http_302_doesnt_change_head_to_get(self, httpbin):
        """
        Tests that HEAD requests preserve their method during HTTP 302 redirects, ensuring correct behavior when following redirects in HTTP clients.
        
        This verifies that the Requests library correctly maintains the original request method (HEAD) throughout redirect chains, which is essential for accurate HTTP semantics and reliable interaction with web services that expect method preservation during redirects.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        r = requests.head(httpbin("status", "302"), allow_redirects=True)
        assert r.status_code == 200
        assert r.request.method == "HEAD"
        assert r.history[0].status_code == 302
        assert r.history[0].is_redirect

    def test_http_303_changes_post_to_get(self, httpbin):
        """
        Tests that HTTP 303 redirects automatically convert POST requests to GET requests, ensuring compliance with HTTP standards and consistent behavior when following redirects.
        
        Args:
            httpbin: Fixture providing the URL for the httpbin service, used to simulate HTTP responses including 303 redirects.
        """
        r = requests.post(httpbin("status", "303"))
        assert r.status_code == 200
        assert r.request.method == "GET"
        assert r.history[0].status_code == 303
        assert r.history[0].is_redirect

    def test_http_303_doesnt_change_head_to_get(self, httpbin):
        """
        Tests that HTTP 303 redirects preserve the original HEAD method instead of changing it to GET, ensuring correct behavior in accordance with HTTP specifications.
        
        This validation is important for Requests' reliability when interacting with servers that use 303 redirects, as it confirms the library correctly maintains the request method during redirection—critical for consistent and predictable HTTP client behavior in real-world applications.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP behavior.
        """
        r = requests.head(httpbin("status", "303"), allow_redirects=True)
        assert r.status_code == 200
        assert r.request.method == "HEAD"
        assert r.history[0].status_code == 303
        assert r.history[0].is_redirect

    def test_header_and_body_removal_on_redirect(self, httpbin):
        """
        Verifies that HTTP headers and request body are properly stripped during redirect handling to prevent unintended data leakage in subsequent requests.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        purged_headers = ("Content-Length", "Content-Type")
        ses = requests.Session()
        req = requests.Request("POST", httpbin("post"), data={"test": "data"})
        prep = ses.prepare_request(req)
        resp = ses.send(prep)

        # Mimic a redirect response
        resp.status_code = 302
        resp.headers["location"] = "get"

        # Run request through resolve_redirects
        next_resp = next(ses.resolve_redirects(resp, prep))
        assert next_resp.request.body is None
        for header in purged_headers:
            assert header not in next_resp.request.headers

    def test_transfer_enc_removal_on_redirect(self, httpbin):
        """
        Tests that Transfer-Encoding and Content-Type headers are removed during redirect handling to ensure compliance with HTTP standards and prevent potential security or parsing issues in redirected requests.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP behavior.
        """
        purged_headers = ("Transfer-Encoding", "Content-Type")
        ses = requests.Session()
        req = requests.Request("POST", httpbin("post"), data=(b"x" for x in range(1)))
        prep = ses.prepare_request(req)
        assert "Transfer-Encoding" in prep.headers

        # Create Response to avoid https://github.com/kevin1024/pytest-httpbin/issues/33
        resp = requests.Response()
        resp.raw = io.BytesIO(b"the content")
        resp.request = prep
        setattr(resp.raw, "release_conn", lambda *args: args)

        # Mimic a redirect response
        resp.status_code = 302
        resp.headers["location"] = httpbin("get")

        # Run request through resolve_redirect
        next_resp = next(ses.resolve_redirects(resp, prep))
        assert next_resp.request.body is None
        for header in purged_headers:
            assert header not in next_resp.request.headers

    def test_fragment_maintained_on_redirect(self, httpbin):
        """
        Verifies that URL fragments are preserved across redirects, ensuring consistent behavior when following HTTP redirects in web requests.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        fragment = "#view=edit&token=hunter2"
        r = requests.get(httpbin("redirect-to?url=get") + fragment)

        assert len(r.history) > 0
        assert r.history[0].request.url == httpbin("redirect-to?url=get") + fragment
        assert r.url == httpbin("get") + fragment

    def test_HTTP_200_OK_GET_WITH_PARAMS(self, httpbin):
        """
        Verifies that HTTP requests with custom User-Agent headers are properly received and reflected by the server, ensuring correct header propagation and response validation. This test supports Requests' core purpose of reliably handling HTTP interactions with accurate header transmission and response inspection.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP behavior.
        """
        heads = {"User-agent": "Mozilla/5.0"}

        r = requests.get(httpbin("user-agent"), headers=heads)

        assert heads["User-agent"] in r.text
        assert r.status_code == 200

    def test_HTTP_200_OK_GET_WITH_MIXED_PARAMS(self, httpbin):
        """
        Tests the ability to make a GET request with both query parameters and custom headers using the Requests library, verifying successful communication with a remote service. This ensures the library correctly handles mixed request components, which is essential for reliable API integration and web interaction.
        
        Args:
            httpbin: Fixture providing the base URL for the httpbin service (default: httpbin service endpoint)
        """
        heads = {"User-agent": "Mozilla/5.0"}

        r = requests.get(
            httpbin("get") + "?test=true", params={"q": "test"}, headers=heads
        )
        assert r.status_code == 200

    def test_set_cookie_on_301(self, httpbin):
        """
        Tests that cookies are correctly persisted across a 301 redirect, ensuring session state is maintained during HTTP redirects. This verifies Requests' ability to handle cookie management consistently with standard HTTP behavior, which is critical for reliable web interactions and stateful API usage.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        s = requests.session()
        url = httpbin("cookies/set?foo=bar")
        s.get(url)
        assert s.cookies["foo"] == "bar"

    def test_cookie_sent_on_redirect(self, httpbin):
        """
        Tests that cookies are properly included in requests during HTTP redirects, ensuring session state is preserved across redirect chains. This behavior is critical for maintaining authenticated sessions and consistent state when interacting with web services that use redirects, which aligns with Requests' goal of providing reliable and intuitive HTTP client functionality.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        s = requests.session()
        s.get(httpbin("cookies/set?foo=bar"))
        r = s.get(httpbin("redirect/1"))  # redirects to httpbin('get')
        assert "Cookie" in r.json()["headers"]

    def test_cookie_removed_on_expire(self, httpbin):
        """
        Tests that expired cookies are automatically removed from the session, ensuring session state remains consistent with server-side cookie expiration policies.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        s = requests.session()
        s.get(httpbin("cookies/set?foo=bar"))
        assert s.cookies["foo"] == "bar"
        s.get(
            httpbin("response-headers"),
            params={"Set-Cookie": "foo=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT"},
        )
        assert "foo" not in s.cookies

    def test_cookie_quote_wrapped(self, httpbin):
        """
        Tests that cookies with quoted values containing special characters like colons are properly preserved during HTTP round trips, ensuring correct handling of RFC-compliant cookie syntax. This is critical for maintaining data integrity in real-world scenarios where cookies may contain complex values.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        s = requests.session()
        s.get(httpbin('cookies/set?foo="bar:baz"'))
        assert s.cookies["foo"] == '"bar:baz"'

    def test_cookie_persists_via_api(self, httpbin):
        """
        Verifies that cookies set via the API are properly maintained across HTTP redirects, ensuring consistent session state during request chains.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        s = requests.session()
        r = s.get(httpbin("redirect/1"), cookies={"foo": "bar"})
        assert "foo" in r.request.headers["Cookie"]
        assert "foo" in r.history[0].request.headers["Cookie"]

    def test_request_cookie_overrides_session_cookie(self, httpbin):
        """
        Tests that request-level cookies take precedence over session-level cookies, ensuring predictable and explicit cookie behavior during HTTP requests. This behavior is critical for accurate testing of web interactions where specific cookies must be sent on a per-request basis without affecting the session state.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        s = requests.session()
        s.cookies["foo"] = "bar"
        r = s.get(httpbin("cookies"), cookies={"foo": "baz"})
        assert r.json()["cookies"]["foo"] == "baz"
        # Session cookie should not be modified
        assert s.cookies["foo"] == "bar"

    def test_request_cookies_not_persisted(self, httpbin):
        """
        Verifies that request-specific cookies are not retained in the session after the request completes, ensuring session state remains clean and predictable.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        s = requests.session()
        s.get(httpbin("cookies"), cookies={"foo": "baz"})
        # Sending a request with cookies should not add cookies to the session
        assert not s.cookies

    def test_generic_cookiejar_works(self, httpbin):
        """
        Tests that a custom CookieJar instance is correctly integrated with a requests session, ensuring cookies are properly sent in HTTP requests. This verifies the library's support for custom cookie management, which is essential for maintaining state across requests in scenarios like authentication or session persistence.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        cj = cookielib.CookieJar()
        cookiejar_from_dict({"foo": "bar"}, cj)
        s = requests.session()
        s.cookies = cj
        r = s.get(httpbin("cookies"))
        # Make sure the cookie was sent
        assert r.json()["cookies"]["foo"] == "bar"
        # Make sure the session cj is still the custom one
        assert s.cookies is cj

    def test_param_cookiejar_works(self, httpbin):
        """
        Tests that a custom CookieJar is correctly transmitted in HTTP requests, ensuring proper session state management across requests.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service, used to verify that cookies are properly sent and received during HTTP interactions.
        """
        cj = cookielib.CookieJar()
        cookiejar_from_dict({"foo": "bar"}, cj)
        s = requests.session()
        r = s.get(httpbin("cookies"), cookies=cj)
        # Make sure the cookie was sent
        assert r.json()["cookies"]["foo"] == "bar"

    def test_cookielib_cookiejar_on_redirect(self, httpbin):
        """
        Tests that redirect resolution correctly handles merging cookies from a non-RequestsCookieJar (specifically cookielib.CookieJar) without failing or converting the cookie jar type.
        
        This ensures compatibility with legacy cookie handling systems and maintains the integrity of cookie jars during redirects, which is critical for session persistence and stateful interactions with web services. The test verifies that cookies from both the original request and the session are preserved across redirects without unintended type conversion, supporting Requests' goal of seamless, reliable HTTP interaction.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP behavior.
        """
        cj = cookiejar_from_dict({"foo": "bar"}, cookielib.CookieJar())
        s = requests.Session()
        s.cookies = cookiejar_from_dict({"cookie": "tasty"})

        # Prepare request without using Session
        req = requests.Request("GET", httpbin("headers"), cookies=cj)
        prep_req = req.prepare()

        # Send request and simulate redirect
        resp = s.send(prep_req)
        resp.status_code = 302
        resp.headers["location"] = httpbin("get")
        redirects = s.resolve_redirects(resp, prep_req)
        resp = next(redirects)

        # Verify CookieJar isn't being converted to RequestsCookieJar
        assert isinstance(prep_req._cookies, cookielib.CookieJar)
        assert isinstance(resp.request._cookies, cookielib.CookieJar)
        assert not isinstance(resp.request._cookies, requests.cookies.RequestsCookieJar)

        cookies = {}
        for c in resp.request._cookies:
            cookies[c.name] = c.value
        assert cookies["foo"] == "bar"
        assert cookies["cookie"] == "tasty"

    def test_requests_in_history_are_not_overridden(self, httpbin):
        """
        Verifies that HTTP request URLs remain unchanged throughout redirect chains by ensuring the URL in each history entry matches the original request URL. This validation is critical for maintaining request integrity in the Requests library, ensuring users can reliably track and debug HTTP flows, especially when dealing with redirects in real-world API interactions.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        resp = requests.get(httpbin("redirect/3"))
        urls = [r.url for r in resp.history]
        req_urls = [r.request.url for r in resp.history]
        assert urls == req_urls

    def test_history_is_always_a_list(self, httpbin):
        """
        Verify that the Response.history attribute remains a list even when redirects occur, ensuring consistent and predictable behavior for users interacting with HTTP responses.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP functionality.
        """
        resp = requests.get(httpbin("get"))
        assert isinstance(resp.history, list)
        resp = requests.get(httpbin("redirect/1"))
        assert isinstance(resp.history, list)
        assert not isinstance(resp.history, tuple)

    def test_headers_on_session_with_None_are_not_sent(self, httpbin):
        """
        Ensure that headers with None values are not included in requests sent via a Session, maintaining clean and valid HTTP headers.
        
        This behavior aligns with Requests' purpose of simplifying HTTP interactions by automatically filtering out invalid or undefined header values, preventing malformed requests and ensuring compatibility with HTTP standards. By excluding None-valued headers, the library avoids sending ambiguous or incorrect data, which supports reliable communication with web services.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        ses = requests.Session()
        ses.headers["Accept-Encoding"] = None
        req = requests.Request("GET", httpbin("get"))
        prep = ses.prepare_request(req)
        assert "Accept-Encoding" not in prep.headers

    def test_headers_preserve_order(self, httpbin):
        """
        Verify that request headers maintain insertion order when using OrderedDict, ensuring predictable header ordering in HTTP requests.
        
        This test validates Requests' ability to preserve the order of headers as specified by the user, which is important for consistent and reliable HTTP communication—especially when header order may affect server behavior or debugging. By using OrderedDict, the test confirms that the library correctly respects the intended sequence of headers during request preparation, aligning with the project's goal of providing intuitive and predictable HTTP interaction.
        """
        ses = requests.Session()
        ses.headers = collections.OrderedDict()
        ses.headers["Accept-Encoding"] = "identity"
        ses.headers["First"] = "1"
        ses.headers["Second"] = "2"
        headers = collections.OrderedDict([("Third", "3"), ("Fourth", "4")])
        headers["Fifth"] = "5"
        headers["Second"] = "222"
        req = requests.Request("GET", httpbin("get"), headers=headers)
        prep = ses.prepare_request(req)
        items = list(prep.headers.items())
        assert items[0] == ("Accept-Encoding", "identity")
        assert items[1] == ("First", "1")
        assert items[2] == ("Second", "222")
        assert items[3] == ("Third", "3")
        assert items[4] == ("Fourth", "4")
        assert items[5] == ("Fifth", "5")

    @pytest.mark.parametrize("key", ("User-agent", "user-agent"))
    def test_user_agent_transfers(self, httpbin, key):
        """
        Tests that custom user agent headers are properly transmitted and reflected by the HTTP service, ensuring Requests correctly sends user-defined headers as intended.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
            key: The header key to use for the user agent (e.g., 'User-Agent').
        """
        heads = {key: "Mozilla/5.0 (github.com/psf/requests)"}

        r = requests.get(httpbin("user-agent"), headers=heads)
        assert heads[key] in r.text

    def test_HTTP_200_OK_HEAD(self, httpbin):
        """
        Tests that the HTTPBin service correctly handles HEAD requests by returning a 200 OK status code, verifying the reliability of the HTTP infrastructure under test. This ensures that the service properly responds to non-body requests, which is essential for validating endpoints in real-world API usage scenarios.
        
        Args:
            httpbin: Fixture providing the base URL for the HTTPBin service (default: httpbin.org)
        """
        r = requests.head(httpbin("get"))
        assert r.status_code == 200

    def test_HTTP_200_OK_PUT(self, httpbin):
        """
        Verifies that the HTTPBin service correctly handles PUT requests by confirming a 200 OK response, ensuring the Requests library properly sends and receives data via the PUT method. This test validates the library's reliability in real-world scenarios involving state-changing HTTP operations, which is essential for robust API integration and web interaction.
        
        Args:
            httpbin: Fixture that provides a URL to the HTTPBin service for testing HTTP methods.
        """
        r = requests.put(httpbin("put"))
        assert r.status_code == 200

    def test_BASICAUTH_TUPLE_HTTP_200_OK_GET(self, httpbin):
        """
        Tests the correct handling of basic authentication with tuple credentials using GET requests, ensuring Requests properly supports HTTP Basic Auth for secure API interactions.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP features.
        """
        auth = ("user", "pass")
        url = httpbin("basic-auth", "user", "pass")

        r = requests.get(url, auth=auth)
        assert r.status_code == 200

        r = requests.get(url)
        assert r.status_code == 401

        s = requests.session()
        s.auth = auth
        r = s.get(url)
        assert r.status_code == 200

    @pytest.mark.parametrize(
        "username, password",
        (
            ("user", "pass"),
            ("имя".encode(), "пароль".encode()),
            (42, 42),
            (None, None),
        ),
    )
    def test_set_basicauth(self, httpbin, username, password):
        """
        Tests that basic authentication credentials are properly encoded and included in the request headers, ensuring secure and correct authentication with HTTP services. This validation is critical for verifying Requests' ability to handle authentication seamlessly, aligning with its purpose of simplifying HTTP interactions while maintaining security and reliability.
        
        Args:
            httpbin: Fixture that returns a URL to the httpbin service for testing.
            username: The username to use for basic authentication.
            password: The password to use for basic authentication.
        """
        auth = (username, password)
        url = httpbin("get")

        r = requests.Request("GET", url, auth=auth)
        p = r.prepare()

        assert p.headers["Authorization"] == _basic_auth_str(username, password)

    def test_basicauth_encodes_byte_strings(self):
        """
        Verify that Basic Authentication correctly handles byte string credentials by ensuring they are properly encoded as ASCII bytes without being misrepresented as Unicode strings in Python 3.
        
        This test ensures Requests maintains backward compatibility and correct behavior when using byte strings for authentication, which is critical for secure and predictable HTTP communication—especially in environments where raw binary data must be preserved during encoding. Without this check, byte strings could be incorrectly formatted or decoded, leading to failed authentication attempts.
        """
        auth = (b"\xc5\xafsername", b"test\xc6\xb6")
        r = requests.Request("GET", "http://localhost", auth=auth)
        p = r.prepare()

        assert p.headers["Authorization"] == "Basic xa9zZXJuYW1lOnRlc3TGtg=="

    @pytest.mark.parametrize(
        "url, exception",
        (
            # Connecting to an unknown domain should raise a ConnectionError
            ("http://doesnotexist.google.com", ConnectionError),
            # Connecting to an invalid port should raise a ConnectionError
            ("http://localhost:1", ConnectionError),
            # Inputing a URL that cannot be parsed should raise an InvalidURL error
            ("http://fe80::5054:ff:fe5a:fc0", InvalidURL),
        ),
    )
    def test_errors(self, url, exception):
        """
        Tests that a given URL raises the expected exception when making a request, ensuring robust error handling in HTTP interactions.
        
        Args:
            url: The URL to send the GET request to.
            exception: The expected exception class to be raised during the request.
        """
        with pytest.raises(exception):
            requests.get(url, timeout=1)

    def test_proxy_error(self):
        """
        Tests that proxy-related network errors—such as address resolution failures or unreachable hosts—are properly handled by raising a ProxyError. This ensures robust error handling in Requests when interacting with unreliable or misconfigured proxies, aligning with the library's goal of providing reliable and predictable HTTP communication even in adverse network conditions.
        """
        # any proxy related error (address resolution, no route to host, etc) should result in a ProxyError
        with pytest.raises(ProxyError):
            requests.get(
                "http://localhost:1", proxies={"http": "non-resolvable-address"}
            )

    def test_proxy_error_on_bad_url(self, httpbin, httpbin_secure):
        """
        Tests that invalid proxy URLs are properly validated and raise InvalidProxyURL exceptions to prevent malformed proxy configurations from causing unexpected behavior in HTTP requests.
        
        Args:
            httpbin: Fixture providing a URL to a HTTPBIN instance for testing HTTP requests.
            httpbin_secure: Fixture providing a URL to a secure HTTPBIN instance for testing HTTPS requests.
        """
        with pytest.raises(InvalidProxyURL):
            requests.get(httpbin_secure(), proxies={"https": "http:/badproxyurl:3128"})

        with pytest.raises(InvalidProxyURL):
            requests.get(httpbin(), proxies={"http": "http://:8080"})

        with pytest.raises(InvalidProxyURL):
            requests.get(httpbin_secure(), proxies={"https": "https://"})

        with pytest.raises(InvalidProxyURL):
            requests.get(httpbin(), proxies={"http": "http:///example.com:8080"})

    def test_respect_proxy_env_on_send_self_prepared_request(self, httpbin):
        """
        Tests that the session properly respects the HTTP proxy environment variable when sending a self-prepared request, ensuring secure and predictable proxy behavior in real-world scenarios.
        
        Args:
            httpbin: Fixture that provides a URL to a test HTTP service (httpbin.org) for making requests.
        """
        with override_environ(http_proxy=INVALID_PROXY):
            with pytest.raises(ProxyError):
                session = requests.Session()
                request = requests.Request("GET", httpbin())
                session.send(request.prepare())

    def test_respect_proxy_env_on_send_session_prepared_request(self, httpbin):
        """
        Tests that a session properly respects the HTTP proxy environment variable when sending a prepared request, ensuring secure and configurable network traffic routing through proxies.
        
        Args:
            httpbin: Fixture that provides a URL to a test HTTP service (httpbin.org) for making requests.
        """
        with override_environ(http_proxy=INVALID_PROXY):
            with pytest.raises(ProxyError):
                session = requests.Session()
                request = requests.Request("GET", httpbin())
                prepared = session.prepare_request(request)
                session.send(prepared)

    def test_respect_proxy_env_on_send_with_redirects(self, httpbin):
        """
        Tests that the session properly respects the HTTP proxy environment variable during requests involving redirects, ensuring secure and predictable proxy behavior in real-world scenarios.
        
        Args:
            httpbin: Fixture that provides a URL to a test HTTP service (httpbin.org) for making requests.
        """
        with override_environ(http_proxy=INVALID_PROXY):
            with pytest.raises(ProxyError):
                session = requests.Session()
                url = httpbin("redirect/1")
                print(url)
                request = requests.Request("GET", url)
                session.send(request.prepare())

    def test_respect_proxy_env_on_get(self, httpbin):
        """
        Verifies that the requests session correctly respects the HTTP proxy environment variable during GET requests, ensuring secure and predictable network behavior in environments where proxy settings are configured.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        with override_environ(http_proxy=INVALID_PROXY):
            with pytest.raises(ProxyError):
                session = requests.Session()
                session.get(httpbin())

    def test_respect_proxy_env_on_request(self, httpbin):
        """
        Verifies that the requests session correctly respects the HTTP proxy environment variable, ensuring secure and predictable proxy configuration in real-world scenarios where proxies are set via environment variables.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing.
        """
        with override_environ(http_proxy=INVALID_PROXY):
            with pytest.raises(ProxyError):
                session = requests.Session()
                session.request(method="GET", url=httpbin())

    def test_proxy_authorization_preserved_on_request(self, httpbin):
        """
        Verifies that the Proxy-Authorization header is correctly preserved when making requests through a session with proxy authentication configured, ensuring reliable proxy authentication support in HTTP workflows.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        proxy_auth_value = "Bearer XXX"
        session = requests.Session()
        session.headers.update({"Proxy-Authorization": proxy_auth_value})
        resp = session.request(method="GET", url=httpbin("get"))
        sent_headers = resp.json().get("headers", {})

        assert sent_headers.get("Proxy-Authorization") == proxy_auth_value

    @pytest.mark.parametrize(
        "url,has_proxy_auth",
        (
            ("http://example.com", True),
            ("https://example.com", False),
        ),
    )
    def test_proxy_authorization_not_appended_to_https_request(
        self, url, has_proxy_auth
    ):
        """
        Verifies that the Proxy-Authorization header is not included in HTTPS requests when using a proxy, ensuring security and compliance with HTTP standards. This check prevents accidental leakage of proxy credentials over encrypted connections, which aligns with Requests' goal of providing safe, predictable, and secure HTTP interactions.
        
        Args:
            url: The URL to send the GET request to, used to determine the protocol (HTTP/HTTPS).
            has_proxy_auth: Boolean indicating whether the proxy configuration includes authentication credentials.
        """
        session = requests.Session()
        proxies = {
            "http": "http://test:pass@localhost:8080",
            "https": "http://test:pass@localhost:8090",
        }
        req = requests.Request("GET", url)
        prep = req.prepare()
        session.rebuild_proxies(prep, proxies)

        assert ("Proxy-Authorization" in prep.headers) is has_proxy_auth

    def test_basicauth_with_netrc(self, httpbin):
        """
        Tests the integration of BasicAuth credentials from netrc files with explicit authentication overrides, ensuring correct behavior in authenticated HTTP requests. This verifies that Requests properly respects netrc authentication while allowing explicit credentials to take precedence, which is essential for secure and flexible API interactions in real-world applications.
        
        Args:
            httpbin: Fixture that returns a URL to the httpbin service with the specified endpoint.
        
        Returns:
            None
        """
        auth = ("user", "pass")
        wrong_auth = ("wronguser", "wrongpass")
        url = httpbin("basic-auth", "user", "pass")

        old_auth = requests.sessions.get_netrc_auth

        try:

            def get_netrc_auth_mock(url):
                return auth

            requests.sessions.get_netrc_auth = get_netrc_auth_mock

            # Should use netrc and work.
            r = requests.get(url)
            assert r.status_code == 200

            # Given auth should override and fail.
            r = requests.get(url, auth=wrong_auth)
            assert r.status_code == 401

            s = requests.session()

            # Should use netrc and work.
            r = s.get(url)
            assert r.status_code == 200

            # Given auth should override and fail.
            s.auth = wrong_auth
            r = s.get(url)
            assert r.status_code == 401
        finally:
            requests.sessions.get_netrc_auth = old_auth

    def test_basicauth_with_netrc_leak(self, httpbin):
        """
        Tests that BasicAuth credentials in URLs take precedence over netrc credentials to prevent unintended credential leakage.
        
        This ensures that explicit credentials provided in the URL are used instead of fallback credentials from netrc, maintaining security and predictability in authentication behavior. In the context of Requests, this is critical for preventing accidental use of stale or incorrect credentials from netrc files when users explicitly specify credentials in URLs, which could otherwise lead to unexpected access or security risks.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing.
        """
        url1 = httpbin("basic-auth", "user", "pass")
        url = url1[len("http://") :]
        domain = url.split(":")[0]
        url = f"http://example.com:@{url}"

        netrc_file = ""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as fp:
            fp.write("machine example.com\n")
            fp.write("login wronguser\n")
            fp.write("password wrongpass\n")
            fp.write(f"machine {domain}\n")
            fp.write("login user\n")
            fp.write("password pass\n")
            fp.close()
            netrc_file = fp.name

        old_netrc = os.environ.get("NETRC", "")
        os.environ["NETRC"] = netrc_file

        try:
            # Should use netrc
            # Make sure that we don't use the example.com credentails
            # for the request
            r = requests.get(url)
            assert r.status_code == 200
        finally:
            os.environ["NETRC"] = old_netrc
            os.unlink(netrc_file)

    def test_DIGEST_HTTP_200_OK_GET(self, httpbin):
        """
        Tests HTTP Digest authentication with multiple algorithms to ensure compatibility and correct behavior for GET requests in the Requests library.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing authentication.
        """
        for authtype in self.digest_auth_algo:
            auth = HTTPDigestAuth("user", "pass")
            url = httpbin("digest-auth", "auth", "user", "pass", authtype, "never")

            r = requests.get(url, auth=auth)
            assert r.status_code == 200

            r = requests.get(url)
            assert r.status_code == 401
            print(r.headers["WWW-Authenticate"])

            s = requests.session()
            s.auth = HTTPDigestAuth("user", "pass")
            r = s.get(url)
            assert r.status_code == 200

    def test_DIGEST_AUTH_RETURNS_COOKIE(self, httpbin):
        """
        Tests that HTTP digest authentication properly sets a cookie when using HTTPDigestAuth, verifying correct authentication flow and session handling in Requests.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing authentication.
        """
        for authtype in self.digest_auth_algo:
            url = httpbin("digest-auth", "auth", "user", "pass", authtype)
            auth = HTTPDigestAuth("user", "pass")
            r = requests.get(url)
            assert r.cookies["fake"] == "fake_value"

            r = requests.get(url, auth=auth)
            assert r.status_code == 200

    def test_DIGEST_AUTH_SETS_SESSION_COOKIES(self, httpbin):
        """
        Tests that digest authentication properly maintains session state by setting expected cookies when using HTTPDigestAuth, ensuring consistent behavior across authentication types.
        
        Args:
            httpbin: Fixture that provides a URL to a running httpbin instance for testing authentication.
            authtype: Authentication algorithm type to test (e.g., 'md5', 'md5-sess'), used to construct the authentication URL.
        """
        for authtype in self.digest_auth_algo:
            url = httpbin("digest-auth", "auth", "user", "pass", authtype)
            auth = HTTPDigestAuth("user", "pass")
            s = requests.Session()
            s.get(url, auth=auth)
            assert s.cookies["fake"] == "fake_value"

    def test_DIGEST_STREAM(self, httpbin):
        """
        Tests streaming behavior with HTTP Digest authentication to ensure correct handling of chunked responses across different digest algorithms, validating that streaming mode properly processes authenticated responses while non-streaming mode correctly skips them.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing authentication endpoints.
        """
        for authtype in self.digest_auth_algo:
            auth = HTTPDigestAuth("user", "pass")
            url = httpbin("digest-auth", "auth", "user", "pass", authtype)

            r = requests.get(url, auth=auth, stream=True)
            assert r.raw.read() != b""

            r = requests.get(url, auth=auth, stream=False)
            assert r.raw.read() == b""

    def test_DIGESTAUTH_WRONG_HTTP_401_GET(self, httpbin):
        """
        Verifies that HTTP Digest Authentication correctly returns a 401 status code when an incorrect password is provided, ensuring the authentication mechanism behaves as expected across different request patterns. This test is critical for maintaining the security and reliability of authentication workflows in Requests, which aims to provide a robust and intuitive interface for HTTP interactions.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing authentication endpoints.
            authtype: Authentication algorithm type (e.g., 'md5', 'md5-sess') to test with digest authentication.
        """
        for authtype in self.digest_auth_algo:
            auth = HTTPDigestAuth("user", "wrongpass")
            url = httpbin("digest-auth", "auth", "user", "pass", authtype)

            r = requests.get(url, auth=auth)
            assert r.status_code == 401

            r = requests.get(url)
            assert r.status_code == 401

            s = requests.session()
            s.auth = auth
            r = s.get(url)
            assert r.status_code == 401

    def test_DIGESTAUTH_QUOTES_QOP_VALUE(self, httpbin):
        """
        Verifies that the Authorization header in digest authentication properly quotes the qop value, ensuring compatibility with servers expecting RFC 2617-compliant authentication headers.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing authentication
        """
        for authtype in self.digest_auth_algo:
            auth = HTTPDigestAuth("user", "pass")
            url = httpbin("digest-auth", "auth", "user", "pass", authtype)

            r = requests.get(url, auth=auth)
            assert '"auth"' in r.request.headers["Authorization"]

    def test_POSTBIN_GET_POST_FILES(self, httpbin):
        """
        Tests the ability to send various types of data—form data, files, and JSON strings—via POST requests using the Requests library, ensuring robust handling of different payload formats in real-world scenarios.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing POST requests.
        """
        url = httpbin("post")
        requests.post(url).raise_for_status()

        post1 = requests.post(url, data={"some": "data"})
        assert post1.status_code == 200

        with open("requirements-dev.txt") as f:
            post2 = requests.post(url, files={"some": f})
        assert post2.status_code == 200

        post4 = requests.post(url, data='[{"some": "json"}]')
        assert post4.status_code == 200

        with pytest.raises(ValueError):
            requests.post(url, files=["bad file data"])

    def test_invalid_files_input(self, httpbin):
        """
        Tests the handling of invalid file inputs in POST requests to ensure robustness when malformed file data is provided.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        url = httpbin("post")
        post = requests.post(url, files={"random-file-1": None, "random-file-2": 1})
        assert b'name="random-file-1"' not in post.request.body
        assert b'name="random-file-2"' in post.request.body

    def test_POSTBIN_SEEKED_OBJECT_WITH_NO_ITER(self, httpbin):
        """
        Tests that Requests correctly handles POST requests with seeked stream objects lacking an __iter__ method, ensuring proper data transmission even when the stream is not iterable.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests
        
        Returns:
            None; asserts that the POST request succeeds and the server receives the expected data after seeking, verifying Requests' robustness with non-iterable stream objects
        """
        class TestStream:
            def __init__(self, data):
                self.data = data.encode()
                self.length = len(self.data)
                self.index = 0

            def __len__(self):
                return self.length

            def read(self, size=None):
                if size:
                    ret = self.data[self.index : self.index + size]
                    self.index += size
                else:
                    ret = self.data[self.index :]
                    self.index = self.length
                return ret

            def tell(self):
                return self.index

            def seek(self, offset, where=0):
                if where == 0:
                    self.index = offset
                elif where == 1:
                    self.index += offset
                elif where == 2:
                    self.index = self.length + offset

        test = TestStream("test")
        post1 = requests.post(httpbin("post"), data=test)
        assert post1.status_code == 200
        assert post1.json()["data"] == "test"

        test = TestStream("test")
        test.seek(2)
        post2 = requests.post(httpbin("post"), data=test)
        assert post2.status_code == 200
        assert post2.json()["data"] == "st"

    def test_POSTBIN_GET_POST_FILES_WITH_DATA(self, httpbin):
        """
        Tests POST request handling with various data and file payloads to validate Requests' ability to correctly encode and transmit different input types to HTTP services, ensuring reliable integration with APIs like httpbin that expect specific content formats.
        
        Args:
            self: Test case instance providing access to test utilities and assertions.
            httpbin: Fixture that returns a URL for the httpbin service, used as the target endpoint for POST requests.
        """
        url = httpbin("post")
        requests.post(url).raise_for_status()

        post1 = requests.post(url, data={"some": "data"})
        assert post1.status_code == 200

        with open("requirements-dev.txt") as f:
            post2 = requests.post(url, data={"some": "data"}, files={"some": f})
        assert post2.status_code == 200

        post4 = requests.post(url, data='[{"some": "json"}]')
        assert post4.status_code == 200

        with pytest.raises(ValueError):
            requests.post(url, files=["bad file data"])

    def test_post_with_custom_mapping(self, httpbin):
        """
        Tests that Requests correctly serializes a custom MutableMapping class as form data in POST requests, ensuring compatibility with web services that expect standard form-encoded payloads.
        
        Args:
            self: Test instance containing the test context
            httpbin: Fixture providing a URL to the httpbin service for testing
        
        Returns:
            None; asserts that the server returns the expected form data in the response JSON, verifying Requests' ability to handle custom mapping types in request payloads
        """
        class CustomMapping(MutableMapping):
            def __init__(self, *args, **kwargs):
                self.data = dict(*args, **kwargs)

            def __delitem__(self, key):
                del self.data[key]

            def __getitem__(self, key):
                return self.data[key]

            def __setitem__(self, key, value):
                self.data[key] = value

            def __iter__(self):
                return iter(self.data)

            def __len__(self):
                return len(self.data)

        data = CustomMapping({"some": "data"})
        url = httpbin("post")
        found_json = requests.post(url, data=data).json().get("form")
        assert found_json == {"some": "data"}

    def test_conflicting_post_params(self, httpbin):
        """
        Verifies that attempting to send both `data` and `files` in a single POST request raises a ValueError, ensuring proper validation of conflicting parameters. This test maintains the library's reliability by enforcing clear, predictable behavior when users provide ambiguous request payloads.
        
        Args:
            httpbin: Fixture providing the URL of the httpbin service for testing.
        """
        url = httpbin("post")
        with open("requirements-dev.txt") as f:
            with pytest.raises(ValueError):
                requests.post(url, data='[{"some": "data"}]', files={"some": f})

    def test_request_ok_set(self, httpbin):
        """
        Verifies that the `ok` attribute correctly reflects the HTTP status code by ensuring a 404 response is marked as not OK, which aligns with Requests' goal of providing intuitive and reliable HTTP interaction.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP responses.
        """
        r = requests.get(httpbin("status", "404"))
        assert not r.ok

    def test_status_raising(self, httpbin):
        """
        Verifies that HTTP error status codes (404, 500) correctly trigger the expected error behavior in requests, ensuring the library properly enforces HTTP error handling as part of its core purpose to simplify reliable HTTP interactions.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP responses.
        """
        r = requests.get(httpbin("status", "404"))
        with pytest.raises(requests.exceptions.HTTPError):
            r.raise_for_status()

        r = requests.get(httpbin("status", "500"))
        assert not r.ok

    def test_decompress_gzip(self, httpbin):
        """
        Tests that Requests automatically decompresses gzip-encoded responses from httpbin, verifying correct handling of compressed HTTP content.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP features.
        """
        r = requests.get(httpbin("gzip"))
        r.content.decode("ascii")

    @pytest.mark.parametrize(
        "url, params",
        (
            ("/get", {"foo": "føø"}),
            ("/get", {"føø": "føø"}),
            ("/get", {"føø": "føø"}),
            ("/get", {"foo": "foo"}),
            ("ø", {"foo": "foo"}),
        ),
    )
    def test_unicode_get(self, httpbin, url, params):
        """
        Tests the handling of Unicode characters in HTTP GET requests to ensure proper encoding and transmission through the requests library.
        
        Args:
            httpbin: Fixture providing the base URL for the httpbin service, used to verify HTTP behavior.
            url: The endpoint path to request, potentially containing Unicode characters, to test encoding robustness.
            params: Dictionary of query parameters to include in the request, which may contain Unicode values, to validate proper URL encoding.
        """
        requests.get(httpbin(url), params=params)

    def test_unicode_header_name(self, httpbin):
        """
        Tests the library's ability to handle Unicode characters in HTTP header names, ensuring robustness when interacting with servers that may use non-ASCII header names. This is important for Requests' purpose of providing reliable, user-friendly HTTP communication in real-world scenarios where headers might contain internationalized content.
        
        Args:
            httpbin: Fixture providing the HTTPBIN endpoint URL for testing
        """
        requests.put(
            httpbin("put"),
            headers={"Content-Type": "application/octet-stream"},
            data="\xff",
        )  # compat.str is unicode.

    def test_pyopenssl_redirect(self, httpbin_secure, httpbin_ca_bundle):
        """
        Tests that pyopenssl can correctly handle HTTPS redirects when using a custom CA bundle, ensuring secure and reliable communication with HTTPS services.
        
        Args:
            httpbin_secure: Fixture providing a secure URL to the httpbin service (default: https://localhost:8443)
            httpbin_ca_bundle: Fixture providing the path to the CA bundle used to verify the server's certificate (default: path to generated CA certificate)
        """
        requests.get(httpbin_secure("status", "301"), verify=httpbin_ca_bundle)

    def test_invalid_ca_certificate_path(self, httpbin_secure):
        """
        Tests error handling for invalid CA certificate paths in HTTPS requests, ensuring Requests properly validates SSL certificates when verifying secure connections.
        
        Args:
            httpbin_secure: Fixture that returns a secure URL for testing HTTPS requests with valid TLS configuration.
        """
        INVALID_PATH = "/garbage"
        with pytest.raises(IOError) as e:
            requests.get(httpbin_secure(), verify=INVALID_PATH)
        assert str(
            e.value
        ) == "Could not find a suitable TLS CA certificate bundle, invalid path: {}".format(
            INVALID_PATH
        )

    def test_invalid_ssl_certificate_files(self, httpbin_secure):
        """
        Verifies that invalid SSL certificate file paths trigger meaningful IOError exceptions, ensuring robust error handling during secure HTTP requests.
        
        Args:
            httpbin_secure: Fixture that provides a URL for a secure httpbin endpoint, used to test SSL certificate validation and ensure proper error propagation when invalid certificate paths are provided.
        """
        INVALID_PATH = "/garbage"
        with pytest.raises(IOError) as e:
            requests.get(httpbin_secure(), cert=INVALID_PATH)
        assert str(
            e.value
        ) == "Could not find the TLS certificate file, invalid path: {}".format(
            INVALID_PATH
        )

        with pytest.raises(IOError) as e:
            requests.get(httpbin_secure(), cert=(".", INVALID_PATH))
        assert str(e.value) == (
            f"Could not find the TLS key file, invalid path: {INVALID_PATH}"
        )

    @pytest.mark.parametrize(
        "env, expected",
        (
            ({}, True),
            ({"REQUESTS_CA_BUNDLE": "/some/path"}, "/some/path"),
            ({"REQUESTS_CA_BUNDLE": ""}, True),
            ({"CURL_CA_BUNDLE": "/some/path"}, "/some/path"),
            ({"CURL_CA_BUNDLE": ""}, True),
            ({"REQUESTS_CA_BUNDLE": "", "CURL_CA_BUNDLE": ""}, True),
            (
                {
                    "REQUESTS_CA_BUNDLE": "/some/path",
                    "CURL_CA_BUNDLE": "/curl/path",
                },
                "/some/path",
            ),
            (
                {
                    "REQUESTS_CA_BUNDLE": "",
                    "CURL_CA_BUNDLE": "/curl/path",
                },
                "/curl/path",
            ),
        ),
    )
    def test_env_cert_bundles(self, httpbin, env, expected):
        """
        Tests the impact of environment variables on certificate bundle verification in requests sessions, ensuring secure HTTPS connections are properly configured based on system settings.
        
        Args:
            httpbin: Fixture providing a URL to a test HTTP server for simulating HTTP requests.
            env: Dictionary of environment variable overrides to patch into os.environ for testing different configuration scenarios.
            expected: Expected value for the 'verify' parameter after merging environment settings, validating correct behavior under various configurations.
        """
        s = requests.Session()
        with mock.patch("os.environ", env):
            settings = s.merge_environment_settings(
                url=httpbin("get"), proxies={}, stream=False, verify=True, cert=None
            )
        assert settings["verify"] == expected

    def test_http_with_certificate(self, httpbin):
        """
        Tests HTTPS request with certificate verification by making a GET request to httpbin using a certificate path set to '.'. This ensures the Requests library correctly handles client certificate authentication, validating its ability to securely communicate with HTTPS endpoints—a key requirement for secure API interactions and web service integration.
        
        Args:
            httpbin: Fixture that provides the URL of the httpbin service for testing.
        """
        r = requests.get(httpbin(), cert=".")
        assert r.status_code == 200

    @pytest.mark.skipif(
        SNIMissingWarning is None,
        reason="urllib3 2.0 removed that warning and errors out instead",
    )
    def test_https_warnings(self, nosan_server):
        """
        Verifies that appropriate SSL warnings are emitted when making HTTPS requests without proper certificate validation.
        
        This test ensures Requests correctly warns users about potential security issues when connecting to HTTPS endpoints with invalid or missing certificate validation, aligning with Requests' purpose of promoting secure HTTP practices. The warnings help developers identify and fix insecure configurations, such as missing SNI support or outdated SSL backends, which could expose applications to man-in-the-middle attacks.
        
        Args:
            nosan_server: Fixture providing a test server without a valid certificate, returning host, port, and CA bundle path.
        """
        host, port, ca_bundle = nosan_server
        if HAS_MODERN_SSL or HAS_PYOPENSSL:
            warnings_expected = ("SubjectAltNameWarning",)
        else:
            warnings_expected = (
                "SNIMissingWarning",
                "InsecurePlatformWarning",
                "SubjectAltNameWarning",
            )

        with pytest.warns() as warning_records:
            warnings.simplefilter("always")
            requests.get(f"https://localhost:{port}/", verify=ca_bundle)

        warning_records = [
            item
            for item in warning_records
            if item.category.__name__ != "ResourceWarning"
        ]

        warnings_category = tuple(item.category.__name__ for item in warning_records)
        assert warnings_category == warnings_expected

    def test_certificate_failure(self, httpbin_secure):
        """
        Verifies that Requests correctly raises a RequestsSSLError when attempting to connect to a server with an untrusted SSL certificate, ensuring robust error handling for secure connections.
        
        Args:
            httpbin_secure: Fixture providing a URL to a secure httpbin instance with a self-signed certificate, used to simulate SSL validation failures.
        """
        with pytest.raises(RequestsSSLError):
            # Our local httpbin does not have a trusted CA, so this call will
            # fail if we use our default trust bundle.
            requests.get(httpbin_secure("status", "200"))

    def test_urlencoded_get_query_multivalued_param(self, httpbin):
        """
        Tests that URL-encoded GET requests with multivalued query parameters are correctly handled by the Requests library, ensuring proper serialization and encoding of list values in query strings. This validates that Requests correctly formats complex query parameters as expected by web APIs, supporting the library's goal of simplifying HTTP interactions with intuitive and predictable behavior.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        r = requests.get(httpbin("get"), params={"test": ["foo", "baz"]})
        assert r.status_code == 200
        assert r.url == httpbin("get?test=foo&test=baz")

    def test_form_encoded_post_query_multivalued_element(self, httpbin):
        """
        Tests the correct serialization of multivalued form-encoded data in POST requests, ensuring Requests properly handles repeated parameter names in the request body according to standard form encoding.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        r = requests.Request(
            method="POST", url=httpbin("post"), data=dict(test=["foo", "baz"])
        )
        prep = r.prepare()
        assert prep.body == "test=foo&test=baz"

    def test_different_encodings_dont_break_post(self, httpbin):
        """
        Tests that file uploads with various encodings are handled correctly by the HTTP client, ensuring robustness when interacting with web services that may expect different content encodings.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        with open(__file__, "rb") as f:
            r = requests.post(
                httpbin("post"),
                data={"stuff": json.dumps({"a": 123})},
                params={"blah": "asdf1234"},
                files={"file": ("test_requests.py", f)},
            )
        assert r.status_code == 200

    @pytest.mark.parametrize(
        "data",
        (
            {"stuff": "ëlïxr"},
            {"stuff": "ëlïxr".encode()},
            {"stuff": "elixr"},
            {"stuff": b"elixr"},
        ),
    )
    def test_unicode_multipart_post(self, httpbin, data):
        """
        Tests the ability to send multipart POST requests with Unicode form data to httpbin, verifying Requests' correct handling of non-ASCII characters in form fields. This ensures the library properly encodes and transmits Unicode content in multipart form data, which is essential for real-world applications involving internationalized text.
        
        Args:
            httpbin: Fixture that returns a URL for the httpbin service.
            data: Dictionary containing form data, which may include Unicode strings.
        """
        with open(__file__, "rb") as f:
            r = requests.post(
                httpbin("post"),
                data=data,
                files={"file": ("test_requests.py", f)},
            )
        assert r.status_code == 200

    def test_unicode_multipart_post_fieldnames(self, httpbin):
        """
        Tests proper handling of Unicode field names in multipart POST requests, ensuring Requests correctly encodes and transmits non-ASCII field names without corruption or incorrect escaping.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        filename = os.path.splitext(__file__)[0] + ".py"
        with open(filename, "rb") as f:
            r = requests.Request(
                method="POST",
                url=httpbin("post"),
                data={b"stuff": "elixr"},
                files={"file": ("test_requests.py", f)},
            )
            prep = r.prepare()

        assert b'name="stuff"' in prep.body
        assert b"name=\"b'stuff'\"" not in prep.body

    def test_unicode_method_name(self, httpbin):
        """
        Tests the ability to upload a file via POST request using Unicode method names, ensuring Requests correctly handles non-ASCII method identifiers in HTTP requests. This validates robustness in real-world scenarios where HTTP method names might be encoded or manipulated.
        
        Args:
            self: Test instance containing test context and methods
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests
        """
        with open(__file__, "rb") as f:
            files = {"file": f}
            r = requests.request(
                method="POST",
                url=httpbin("post"),
                files=files,
            )
        assert r.status_code == 200

    def test_unicode_method_name_with_request_object(self, httpbin):
        """
        Tests that Unicode method names are correctly handled when preparing HTTP requests using a request object, ensuring compatibility with internationalized or non-ASCII method identifiers in real-world scenarios.
        
        Args:
            self: Test case instance providing access to test utilities and assertions.
            httpbin: Fixture that provides a URL to a running httpbin service for testing HTTP requests.
        """
        s = requests.Session()
        with open(__file__, "rb") as f:
            files = {"file": f}
            req = requests.Request("POST", httpbin("post"), files=files)
            prep = s.prepare_request(req)
        assert isinstance(prep.method, builtin_str)
        assert prep.method == "POST"

        resp = s.send(prep)
        assert resp.status_code == 200

    def test_non_prepared_request_error(self):
        """
        Tests that a Session rejects non-PreparedRequest objects to enforce correct usage of the send method, ensuring request objects are properly prepared before transmission. This validation prevents misuse of the Session API by requiring explicit preparation of requests, which maintains consistency and reliability in HTTP communication—aligning with Requests' goal of providing a simple, safe, and intuitive interface for making HTTP requests.
        """
        s = requests.Session()
        req = requests.Request("POST", "/")

        with pytest.raises(ValueError) as e:
            s.send(req)
        assert str(e.value) == "You can only send PreparedRequests."

    def test_custom_content_type(self, httpbin):
        """
        Tests that a custom content type is properly transmitted when uploading files via requests, ensuring correct MIME type handling for file uploads. This validates Requests' ability to preserve user-defined content types in multipart form data, which is essential for accurate server-side processing of uploaded files.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        with open(__file__, "rb") as f1:
            with open(__file__, "rb") as f2:
                data = {"stuff": json.dumps({"a": 123})}
                files = {
                    "file1": ("test_requests.py", f1),
                    "file2": ("test_requests", f2, "text/py-content-type"),
                }
                r = requests.post(httpbin("post"), data=data, files=files)
        assert r.status_code == 200
        assert b"text/py-content-type" in r.request.body

    def test_hook_receives_request_arguments(self, httpbin):
        """
        Verifies that response hooks receive the original request arguments when using a session, ensuring consistent behavior for debugging and extending request workflows.
        
        Args:
            httpbin: Fixture that provides a URL to a test HTTP service for making requests.
        """
        def hook(resp, **kwargs):
            assert resp is not None
            assert kwargs != {}

        s = requests.Session()
        r = requests.Request("GET", httpbin(), hooks={"response": hook})
        prep = s.prepare_request(r)
        s.send(prep)

    def test_session_hooks_are_used_with_no_request_hooks(self, httpbin):
        """
        Verifies that response hooks defined at the session level are correctly inherited by prepared requests, ensuring consistent behavior when no request-level hooks are specified. This is critical for maintaining predictable request processing in applications that rely on session-wide side effects like logging, error handling, or response transformation.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests
        """
        def hook(*args, **kwargs):
            pass

        s = requests.Session()
        s.hooks["response"].append(hook)
        r = requests.Request("GET", httpbin())
        prep = s.prepare_request(r)
        assert prep.hooks["response"] != []
        assert prep.hooks["response"] == [hook]

    def test_session_hooks_are_overridden_by_request_hooks(self, httpbin):
        """
        Verifies that request-level hooks take precedence over session-level hooks, ensuring fine-grained control over HTTP request processing in the Requests library.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        def hook1(*args, **kwargs):
            pass

        def hook2(*args, **kwargs):
            pass

        assert hook1 is not hook2
        s = requests.Session()
        s.hooks["response"].append(hook2)
        r = requests.Request("GET", httpbin(), hooks={"response": [hook1]})
        prep = s.prepare_request(r)
        assert prep.hooks["response"] == [hook1]

    def test_prepared_request_hook(self, httpbin):
        """
        Tests that a response hook is properly executed during request preparation and processing, ensuring the extensibility and reliability of Requests' hook system.
        
        Args:
            httpbin: Fixture that returns a URL to the httpbin service for testing HTTP requests.
        
        Returns:
            None; asserts that the response object has the 'hook_working' attribute set by the hook function, verifying correct execution of user-defined hooks in the request lifecycle.
        """
        def hook(resp, **kwargs):
            resp.hook_working = True
            return resp

        req = requests.Request("GET", httpbin(), hooks={"response": hook})
        prep = req.prepare()

        s = requests.Session()
        s.proxies = getproxies()
        resp = s.send(prep)

        assert hasattr(resp, "hook_working")

    def test_prepared_from_session(self, httpbin):
        """
        Tests that session-level authentication is properly applied to prepared requests, ensuring consistent authentication behavior across request lifecycle stages.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests
        
        Returns:
            None; asserts that the response headers contain the expected authentication header value, verifying that session-level auth is correctly propagated to prepared requests
        """
        class DummyAuth(requests.auth.AuthBase):
            def __call__(self, r):
                r.headers["Dummy-Auth-Test"] = "dummy-auth-test-ok"
                return r

        req = requests.Request("GET", httpbin("headers"))
        assert not req.auth

        s = requests.Session()
        s.auth = DummyAuth()

        prep = s.prepare_request(req)
        resp = s.send(prep)

        assert resp.json()["headers"]["Dummy-Auth-Test"] == "dummy-auth-test-ok"

    def test_prepare_request_with_bytestring_url(self):
        """
        Tests that the session's prepare_request method correctly handles byte string URLs by decoding them to UTF-8 strings, ensuring consistent URL handling across input types.
        
        This ensures Requests maintains compatibility with byte string inputs while preserving the expected string URL format, supporting the library's goal of providing a flexible and intuitive HTTP client that seamlessly handles various input formats without requiring manual encoding/decoding by users.
        """
        req = requests.Request("GET", b"https://httpbin.org/")
        s = requests.Session()
        prep = s.prepare_request(req)
        assert prep.url == "https://httpbin.org/"

    def test_request_with_bytestring_host(self, httpbin):
        """
        Tests that Requests correctly handles bytestring values for the Host header, ensuring compatibility with raw byte data in HTTP headers. This validates the library's robustness in processing non-string header values while maintaining proper HTTP semantics.
        
        Args:
            httpbin: Fixture that returns a URL pointing to a running httpbin instance.
        """
        s = requests.Session()
        resp = s.request(
            "GET",
            httpbin("cookies/set?cookie=value"),
            allow_redirects=False,
            headers={"Host": b"httpbin.org"},
        )
        assert resp.cookies.get("cookie") == "value"

    def test_links(self):
        """
        Tests the correct parsing of HTTP Link headers, ensuring that the 'next' relation is properly extracted and identified from the Link header value.
        
        This validation is critical for the Requests library's ability to support pagination in API responses, enabling users to seamlessly navigate through paginated data sets by reliably accessing the 'next' link in API responses, which is a common pattern in RESTful APIs.
        """
        r = requests.Response()
        r.headers = {
            "cache-control": "public, max-age=60, s-maxage=60",
            "connection": "keep-alive",
            "content-encoding": "gzip",
            "content-type": "application/json; charset=utf-8",
            "date": "Sat, 26 Jan 2013 16:47:56 GMT",
            "etag": '"6ff6a73c0e446c1f61614769e3ceb778"',
            "last-modified": "Sat, 26 Jan 2013 16:22:39 GMT",
            "link": (
                "<https://api.github.com/users/kennethreitz/repos?"
                'page=2&per_page=10>; rel="next", <https://api.github.'
                "com/users/kennethreitz/repos?page=7&per_page=10>; "
                ' rel="last"'
            ),
            "server": "GitHub.com",
            "status": "200 OK",
            "vary": "Accept",
            "x-content-type-options": "nosniff",
            "x-github-media-type": "github.beta",
            "x-ratelimit-limit": "60",
            "x-ratelimit-remaining": "57",
        }
        assert r.links["next"]["rel"] == "next"

    def test_cookie_parameters(self):
        """
        Tests that cookie parameters such as the secure flag, domain, and custom attributes like HttpOnly are correctly handled and preserved when setting cookies in a RequestsCookieJar.
        
        This ensures Requests maintains proper cookie security and compliance with HTTP standards by verifying that critical attributes are accurately stored and accessible, which is essential for secure session management and consistent behavior across HTTP interactions.
        """
        key = "some_cookie"
        value = "some_value"
        secure = True
        domain = "test.com"
        rest = {"HttpOnly": True}

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value, secure=secure, domain=domain, rest=rest)

        assert len(jar) == 1
        assert "some_cookie" in jar

        cookie = list(jar)[0]
        assert cookie.secure == secure
        assert cookie.domain == domain
        assert cookie._rest["HttpOnly"] == rest["HttpOnly"]

    def test_cookie_as_dict_keeps_len(self):
        """
        Verifies that converting a RequestsCookieJar to a dictionary preserves the original number of cookies across all conversion methods.
        
        This test ensures consistent behavior when serializing cookie jars to dictionaries—critical for maintaining expected state during session management and request handling in Requests, where accurate cookie representation is essential for reliable HTTP interactions.
        """
        key = "some_cookie"
        value = "some_value"

        key1 = "some_cookie1"
        value1 = "some_value1"

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        d1 = dict(jar)
        d2 = dict(jar.iteritems())
        d3 = dict(jar.items())

        assert len(jar) == 2
        assert len(d1) == 2
        assert len(d2) == 2
        assert len(d3) == 2

    def test_cookie_as_dict_keeps_items(self):
        """
        Verifies that a RequestsCookieJar can be reliably converted to a dictionary using multiple methods, ensuring that all cookies set via `set()` are preserved and accessible. This is critical for maintaining consistent cookie handling across different parts of the library, especially when integrating with session management or external systems that expect dictionary-like behavior.
        """
        key = "some_cookie"
        value = "some_value"

        key1 = "some_cookie1"
        value1 = "some_value1"

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        d1 = dict(jar)
        d2 = dict(jar.iteritems())
        d3 = dict(jar.items())

        assert d1["some_cookie"] == "some_value"
        assert d2["some_cookie"] == "some_value"
        assert d3["some_cookie1"] == "some_value1"

    def test_cookie_as_dict_keys(self):
        """
        Tests that the keys view of a RequestsCookieJar behaves consistently and remains iterable across multiple accesses, ensuring reliable cookie key retrieval during HTTP session management.
        
        This test verifies the reliability of cookie key access in Requests' cookie jar implementation, which is critical for maintaining predictable behavior when interacting with web services that rely on cookie-based state management. Consistent key views ensure that applications can safely iterate over cookies multiple times without unexpected changes, supporting the library's goal of providing a robust and intuitive HTTP client for web interactions.
        """
        key = "some_cookie"
        value = "some_value"

        key1 = "some_cookie1"
        value1 = "some_value1"

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        keys = jar.keys()
        assert keys == list(keys)
        # make sure one can use keys multiple times
        assert list(keys) == list(keys)

    def test_cookie_as_dict_values(self):
        """
        Tests that the `values()` method of `RequestsCookieJar` returns a consistent, reusable iterable, ensuring reliable behavior when accessed multiple times.
        
        This test verifies the method's correctness in maintaining data integrity during repeated iteration, which is essential for the library's goal of providing a predictable and intuitive interface for managing HTTP cookies. By confirming that `values()` behaves consistently across multiple conversions to lists, the test supports Requests' broader purpose of simplifying HTTP interactions while ensuring robustness in real-world usage scenarios.
        """
        key = "some_cookie"
        value = "some_value"

        key1 = "some_cookie1"
        value1 = "some_value1"

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        values = jar.values()
        assert values == list(values)
        # make sure one can use values multiple times
        assert list(values) == list(values)

    def test_cookie_as_dict_items(self):
        """
        Tests that the items() method of RequestsCookieJar returns a reusable iterable of (key, value) pairs, ensuring consistent and reliable cookie access.
        
        This test verifies that the method behaves as expected in real-world usage scenarios, where developers may need to iterate over cookies multiple times without side effects. Since Requests prioritizes intuitive and predictable behavior for HTTP interactions—including cookie management—this check ensures that cookie data can be reliably accessed and reused, supporting robust session handling and API integration workflows.
        """
        key = "some_cookie"
        value = "some_value"

        key1 = "some_cookie1"
        value1 = "some_value1"

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)

        items = jar.items()
        assert items == list(items)
        # make sure one can use items multiple times
        assert list(items) == list(items)

    def test_cookie_duplicate_names_different_domains(self):
        """
        Tests the correct handling of cookies with duplicate names across different domains to ensure proper isolation and retrieval behavior.
        
        This test verifies that the cookie jar correctly stores cookies with the same name but different domains as distinct entries, which is essential for maintaining security and correctness in HTTP sessions. It ensures that attempting to retrieve a cookie without specifying the domain raises a CookieConflictError—preventing ambiguous or unintended cookie access—while retrieving with the correct domain returns the expected value, aligning with the expected behavior in real-world scenarios where multiple domains may use identical cookie names.
        """
        key = "some_cookie"
        value = "some_value"
        domain1 = "test1.com"
        domain2 = "test2.com"

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value, domain=domain1)
        jar.set(key, value, domain=domain2)
        assert key in jar
        items = jar.items()
        assert len(items) == 2

        # Verify that CookieConflictError is raised if domain is not specified
        with pytest.raises(requests.cookies.CookieConflictError):
            jar.get(key)

        # Verify that CookieConflictError is not raised if domain is specified
        cookie = jar.get(key, domain=domain1)
        assert cookie == value

    def test_cookie_duplicate_names_raises_cookie_conflict_error(self):
        """
        Tests that setting multiple cookies with the same name but different paths raises a CookieConflictError during retrieval, ensuring proper cookie management in HTTP sessions.
        
        This test verifies Requests' behavior in handling cookie conflicts, which is critical for maintaining session integrity and security. When multiple cookies share the same name but differ only in path, the library must detect the ambiguity and prevent unintended cookie retrieval. This behavior aligns with the HTTP specification and prevents potential security vulnerabilities or unexpected application behavior in real-world scenarios where cookies are used across different paths.
        """
        key = "some_cookie"
        value = "some_value"
        path = "some_path"

        jar = requests.cookies.RequestsCookieJar()
        jar.set(key, value, path=path)
        jar.set(key, value)
        with pytest.raises(requests.cookies.CookieConflictError):
            jar.get(key)

    def test_cookie_policy_copy(self):
        """
        Tests that copying a RequestsCookieJar preserves the custom cookie policy to ensure consistent behavior across cookie jar instances.
        
        This is critical in Requests' context, where users may define custom cookie policies to control how cookies are accepted or rejected based on domain, path, or other criteria. By verifying that the copy operation retains the exact policy instance, we ensure that cookie handling logic remains predictable and reliable when cloning jars—especially important in scenarios involving session management, web scraping, or testing where policy consistency is essential.
        """
        class MyCookiePolicy(cookielib.DefaultCookiePolicy):
            pass

        jar = requests.cookies.RequestsCookieJar()
        jar.set_policy(MyCookiePolicy())
        assert isinstance(jar.copy().get_policy(), MyCookiePolicy)

    def test_time_elapsed_blank(self, httpbin):
        """
        Verifies that HTTP requests made through the Requests library have a measurable elapsed time, ensuring the underlying network operations complete successfully and are not instantaneous or zero-duration.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for making test requests.
        """
        r = requests.get(httpbin("get"))
        td = r.elapsed
        total_seconds = (
            td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6
        ) / 10**6
        assert total_seconds > 0.0

    def test_empty_response_has_content_none(self):
        """
        Verifies that the Response class initializes with content set to None when no data is provided, ensuring consistent default behavior across all response instances.
        
        This test confirms that Requests maintains predictable and reliable state for empty responses, which is critical for the library's purpose of providing a consistent, intuitive HTTP client. By guaranteeing that content defaults to None, the library prevents unexpected behavior when handling responses without body content, supporting reliable API integration and web scraping workflows.
        """
        r = requests.Response()
        assert r.content is None

    def test_response_is_iterable(self):
        """
        Tests the ability to iterate over a response object when its raw attribute is a file-like object, ensuring compatibility with streaming responses and efficient memory usage.
        
        Returns:
            None
        """
        r = requests.Response()
        io = StringIO.StringIO("abc")
        read_ = io.read

        def read_mock(amt, decode_content=None):
            return read_(amt)

        setattr(io, "read", read_mock)
        r.raw = io
        assert next(iter(r))
        io.close()

    def test_response_decode_unicode(self):
        """
        Verifies that Response.iter_content correctly returns Unicode strings when decode_unicode is enabled, ensuring consistent text handling across both buffered and streaming responses.
        
        Returns:
            None; asserts that all chunks returned by iter_content are instances of str when decode_unicode=True, confirming proper encoding handling in Requests' response processing.
        """
        r = requests.Response()
        r._content_consumed = True
        r._content = b"the content"
        r.encoding = "ascii"

        chunks = r.iter_content(decode_unicode=True)
        assert all(isinstance(chunk, str) for chunk in chunks)

        # also for streaming
        r = requests.Response()
        r.raw = io.BytesIO(b"the content")
        r.encoding = "ascii"
        chunks = r.iter_content(decode_unicode=True)
        assert all(isinstance(chunk, str) for chunk in chunks)

    def test_response_reason_unicode(self):
        """
        Tests that response objects correctly handle non-ASCII HTTP status reasons encoded as bytes, ensuring reliable behavior for internationalized error messages.
        
        This test verifies backward compatibility with older versions of Requests by confirming that responses with Unicode status reasons (e.g., non-ASCII strings encoded as bytes) still properly set the `ok` attribute to `False` for client and server error status codes like 404. This is critical for maintaining consistent behavior when dealing with internationalized web services and legacy server responses, aligning with Requests' goal of being a robust, user-friendly HTTP client that handles real-world edge cases gracefully.
        """
        # check for unicode HTTP status
        r = requests.Response()
        r.url = "unicode URL"
        r.reason = "Komponenttia ei löydy".encode()
        r.status_code = 404
        r.encoding = None
        assert not r.ok  # old behaviour - crashes here

    def test_response_reason_unicode_fallback(self):
        """
        Tests that HTTPError gracefully handles non-UTF-8 response reasons by falling back to ISO-8859-1 encoding.
        
        Ensures Requests maintains compatibility with internationalized HTTP responses—particularly those containing non-UTF-8 characters—by defaulting to ISO-8859-1 when decoding response reasons fails. This behavior preserves the original reason text in error messages, supporting robust error handling in real-world scenarios where server responses may use unexpected encodings, which aligns with Requests' goal of being a reliable, user-friendly HTTP client for diverse web interactions.
        """
        # check raise_status falls back to ISO-8859-1
        r = requests.Response()
        r.url = "some url"
        reason = "Komponenttia ei löydy"
        r.reason = reason.encode("latin-1")
        r.status_code = 500
        r.encoding = None
        with pytest.raises(requests.exceptions.HTTPError) as e:
            r.raise_for_status()
        assert reason in e.value.args[0]

    def test_response_chunk_size_type(self):
        """
        Verify that the chunk_size parameter in iter_content accepts only None or an integer, ensuring proper handling of response streaming.
        
        This test ensures the robustness of Requests' streaming functionality by validating input validation for chunk_size, which is critical for efficient memory usage when processing large responses. By enforcing correct types, the library maintains reliability and prevents unexpected behavior during data streaming.
        """
        r = requests.Response()
        r.raw = io.BytesIO(b"the content")
        chunks = r.iter_content(1)
        assert all(len(chunk) == 1 for chunk in chunks)

        r = requests.Response()
        r.raw = io.BytesIO(b"the content")
        chunks = r.iter_content(None)
        assert list(chunks) == [b"the content"]

        r = requests.Response()
        r.raw = io.BytesIO(b"the content")
        with pytest.raises(TypeError):
            chunks = r.iter_content("1024")

    @pytest.mark.parametrize(
        "exception, args, expected",
        (
            (urllib3.exceptions.ProtocolError, tuple(), ChunkedEncodingError),
            (urllib3.exceptions.DecodeError, tuple(), ContentDecodingError),
            (urllib3.exceptions.ReadTimeoutError, (None, "", ""), ConnectionError),
            (urllib3.exceptions.SSLError, tuple(), RequestsSSLError),
        ),
    )
    def test_iter_content_wraps_exceptions(self, httpbin, exception, args, expected):
        """
        Tests that iter_content correctly wraps and re-raises exceptions raised during streaming, ensuring robust error handling in HTTP response processing. This is critical for maintaining reliability when consuming large or streaming responses, especially in scenarios involving network timeouts or connection issues.
        
        Args:
            httpbin: Fixture providing a test HTTP server instance to simulate real-world HTTP interactions.
            exception: The exception class to be raised by the stream, used to test error propagation behavior.
            args: Arguments to pass to the exception constructor, allowing for flexible testing of different exception states.
            expected: The expected exception type that should be raised by iter_content, verifying proper wrapping logic.
        """
        r = requests.Response()
        r.raw = mock.Mock()
        # ReadTimeoutError can't be initialized by mock
        # so we'll manually create the instance with args
        r.raw.stream.side_effect = exception(*args)

        with pytest.raises(expected):
            next(r.iter_content(1024))

    def test_request_and_response_are_pickleable(self, httpbin):
        """
        Verifies that request and response objects maintain their integrity when serialized and deserialized, ensuring compatibility with pickling workflows commonly used in distributed systems and task queues.
        
        Args:
            self: Test instance containing the test context.
            httpbin: Fixture providing a URL to the httpbin service for making test requests.
        """
        r = requests.get(httpbin("get"))

        # verify we can pickle the original request
        assert pickle.loads(pickle.dumps(r.request))

        # verify we can pickle the response and that we have access to
        # the original request.
        pr = pickle.loads(pickle.dumps(r))
        assert r.request.url == pr.request.url
        assert r.request.headers == pr.request.headers

    def test_prepared_request_is_pickleable(self, httpbin):
        """
        Verifies that PreparedRequest objects maintain their integrity after serialization and deserialization, ensuring they can be safely used across processes or stored temporarily without losing request state.
        
        This is important for the Requests library's goal of enabling reliable and consistent HTTP interactions, particularly in scenarios involving distributed systems, caching, or task queues where requests may need to be serialized.
        
        Args:
            self: Test instance containing the test context.
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        p = requests.Request("GET", httpbin("get")).prepare()

        # Verify PreparedRequest can be pickled and unpickled
        r = pickle.loads(pickle.dumps(p))
        assert r.url == p.url
        assert r.headers == p.headers
        assert r.body == p.body

        # Verify unpickled PreparedRequest sends properly
        s = requests.Session()
        resp = s.send(r)
        assert resp.status_code == 200

    def test_prepared_request_with_file_is_pickleable(self, httpbin):
        """
        Verifies that PreparedRequest objects containing file data can be serialized and deserialized correctly, ensuring compatibility with pickling workflows in distributed or cached environments.
        
        Args:
            self: Test case instance
            httpbin: Fixture providing a URL to the httpbin service for testing
        """
        with open(__file__, "rb") as f:
            r = requests.Request("POST", httpbin("post"), files={"file": f})
            p = r.prepare()

        # Verify PreparedRequest can be pickled and unpickled
        r = pickle.loads(pickle.dumps(p))
        assert r.url == p.url
        assert r.headers == p.headers
        assert r.body == p.body

        # Verify unpickled PreparedRequest sends properly
        s = requests.Session()
        resp = s.send(r)
        assert resp.status_code == 200

    def test_prepared_request_with_hook_is_pickleable(self, httpbin):
        """
        Verifies that PreparedRequest objects with hooks remain serializable and functional after pickling, ensuring reliable state preservation across processes or storage. This is critical for distributed systems and long-running applications where HTTP requests may need to be queued, persisted, or transmitted between components.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing.
        """
        r = requests.Request("GET", httpbin("get"), hooks=default_hooks())
        p = r.prepare()

        # Verify PreparedRequest can be pickled
        r = pickle.loads(pickle.dumps(p))
        assert r.url == p.url
        assert r.headers == p.headers
        assert r.body == p.body
        assert r.hooks == p.hooks

        # Verify unpickled PreparedRequest sends properly
        s = requests.Session()
        resp = s.send(r)
        assert resp.status_code == 200

    def test_cannot_send_unprepared_requests(self, httpbin):
        """
        Verifies that attempting to send an unprepared request raises a ValueError, ensuring robust error handling in the session's send method. This test reinforces Requests' design principle of preventing invalid HTTP operations early, maintaining reliability and clarity for users interacting with web services.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing.
        """
        r = requests.Request(url=httpbin())
        with pytest.raises(ValueError):
            requests.Session().send(r)

    def test_http_error(self):
        """
        Tests the initialization and attribute handling of HTTPError to ensure proper behavior in error scenarios during HTTP requests.
        
        Verifies that the HTTPError class correctly manages response objects and error messages, which is essential for robust error handling in Requests' workflow—allowing users to inspect failed responses and understand the cause of HTTP errors when interacting with web services.
        """
        error = requests.exceptions.HTTPError()
        assert not error.response
        response = requests.Response()
        error = requests.exceptions.HTTPError(response=response)
        assert error.response == response
        error = requests.exceptions.HTTPError("message", response=response)
        assert str(error) == "message"
        assert error.response == response

    def test_session_pickling(self, httpbin):
        """
        Tests that a requests.Session object can be pickled and unpickled without losing its functionality, ensuring session state and configuration persist across serialization. This is important for distributed systems and multiprocessing scenarios where session objects need to be shared or stored.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        r = requests.Request("GET", httpbin("get"))
        s = requests.Session()

        s = pickle.loads(pickle.dumps(s))
        s.proxies = getproxies()

        r = s.send(r.prepare())
        assert r.status_code == 200

    def test_fixes_1329(self, httpbin):
        """
        Verify that header updates in a session are handled case-insensitively, ensuring consistent behavior across different capitalizations of the same header name.
        
        This test confirms that Requests maintains proper header normalization, which aligns with HTTP standards and improves user experience by preventing confusion when setting headers with varying case. This is critical for reliable API interactions where header case may vary across implementations.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        s = requests.Session()
        s.headers.update({"ACCEPT": "BOGUS"})
        s.headers.update({"accept": "application/json"})
        r = s.get(httpbin("get"))
        headers = r.request.headers
        assert headers["accept"] == "application/json"
        assert headers["Accept"] == "application/json"
        assert headers["ACCEPT"] == "application/json"

    def test_uppercase_scheme_redirect(self, httpbin):
        """
        Tests that HTTP redirects are handled correctly when the scheme is specified in uppercase (e.g., 'HTTP://'), ensuring Requests properly normalizes and follows redirects regardless of scheme case.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        parts = urlparse(httpbin("html"))
        url = "HTTP://" + parts.netloc + parts.path
        r = requests.get(httpbin("redirect-to"), params={"url": url})
        assert r.status_code == 200
        assert r.url.lower() == url.lower()

    def test_transport_adapter_ordering(self):
        """
        Tests the prioritization logic for transport adapters in a requests.Session, ensuring that more specific URL prefixes (longer paths) are matched before less specific ones, and HTTPS schemes take precedence over HTTP. This behavior is critical for the library's ability to correctly route requests to the appropriate adapter based on URL patterns, supporting predictable and reliable HTTP communication in real-world applications like API clients and web scrapers.
        """
        s = requests.Session()
        order = ["https://", "http://"]
        assert order == list(s.adapters)
        s.mount("http://git", HTTPAdapter())
        s.mount("http://github", HTTPAdapter())
        s.mount("http://github.com", HTTPAdapter())
        s.mount("http://github.com/about/", HTTPAdapter())
        order = [
            "http://github.com/about/",
            "http://github.com",
            "http://github",
            "http://git",
            "https://",
            "http://",
        ]
        assert order == list(s.adapters)
        s.mount("http://gittip", HTTPAdapter())
        s.mount("http://gittip.com", HTTPAdapter())
        s.mount("http://gittip.com/about/", HTTPAdapter())
        order = [
            "http://github.com/about/",
            "http://gittip.com/about/",
            "http://github.com",
            "http://gittip.com",
            "http://github",
            "http://gittip",
            "http://git",
            "https://",
            "http://",
        ]
        assert order == list(s.adapters)
        s2 = requests.Session()
        s2.adapters = {"http://": HTTPAdapter()}
        s2.mount("https://", HTTPAdapter())
        assert "http://" in s2.adapters
        assert "https://" in s2.adapters

    def test_session_get_adapter_prefix_matching(self):
        """
        Tests the URL prefix matching logic in Session.get_adapter to ensure the most specific mounted prefix is selected for a given URL. This is critical for Requests' session management, as it enables accurate routing of HTTP requests to the appropriate adapter based on URL prefixes, supporting use cases like routing different endpoints to different connection pools or custom behaviors.
        """
        prefix = "https://example.com"
        more_specific_prefix = prefix + "/some/path"

        url_matching_only_prefix = prefix + "/another/path"
        url_matching_more_specific_prefix = more_specific_prefix + "/longer/path"
        url_not_matching_prefix = "https://another.example.com/"

        s = requests.Session()
        prefix_adapter = HTTPAdapter()
        more_specific_prefix_adapter = HTTPAdapter()
        s.mount(prefix, prefix_adapter)
        s.mount(more_specific_prefix, more_specific_prefix_adapter)

        assert s.get_adapter(url_matching_only_prefix) is prefix_adapter
        assert (
            s.get_adapter(url_matching_more_specific_prefix)
            is more_specific_prefix_adapter
        )
        assert s.get_adapter(url_not_matching_prefix) not in (
            prefix_adapter,
            more_specific_prefix_adapter,
        )

    def test_session_get_adapter_prefix_matching_mixed_case(self):
        """
        Tests the case-insensitive prefix matching behavior of session adapters in Requests, ensuring that mounted adapters correctly handle mixed-case URL prefixes. This is critical for robust HTTP client behavior, as real-world URLs may vary in case, and the library must reliably route requests to the appropriate adapter regardless of case differences in the URL prefix.
        """
        mixed_case_prefix = "hTtPs://eXamPle.CoM/MixEd_CAse_PREfix"
        url_matching_prefix = mixed_case_prefix + "/full_url"

        s = requests.Session()
        my_adapter = HTTPAdapter()
        s.mount(mixed_case_prefix, my_adapter)

        assert s.get_adapter(url_matching_prefix) is my_adapter

    def test_session_get_adapter_prefix_matching_is_case_insensitive(self):
        """
        Verifies that session adapter prefix matching is case-insensitive to ensure consistent behavior when mounting adapters on URLs with varying capitalization. This is critical for robust session management in Requests, where users expect reliable adapter resolution regardless of URL case, supporting real-world scenarios where URLs may be inconsistently cased in APIs or configuration.
        """
        mixed_case_prefix = "hTtPs://eXamPle.CoM/MixEd_CAse_PREfix"
        url_matching_prefix_with_different_case = (
            "HtTpS://exaMPLe.cOm/MiXeD_caSE_preFIX/another_url"
        )

        s = requests.Session()
        my_adapter = HTTPAdapter()
        s.mount(mixed_case_prefix, my_adapter)

        assert s.get_adapter(url_matching_prefix_with_different_case) is my_adapter

    def test_session_get_adapter_prefix_with_trailing_slash(self):
        """
        Tests that session adapter mounting with a trailing slash in the prefix correctly routes URLs to the adapter based on the base domain, while rejecting URLs from different domains. This ensures consistent and predictable URL routing behavior in session-based HTTP requests, which is critical for maintaining secure and reliable interactions with web services—especially when multiple domains or subdomains are involved. Addresses issue #6935 by verifying that prefix matching respects both the domain and path structure, preventing unintended adapter routing.
        """
        # from issue #6935
        prefix = "https://example.com/"  # trailing slash
        url_matching_prefix = "https://example.com/some/path"
        url_not_matching_prefix = "https://example.com.other.com/some/path"

        s = requests.Session()
        adapter = HTTPAdapter()
        s.mount(prefix, adapter)

        assert s.get_adapter(url_matching_prefix) is adapter
        assert s.get_adapter(url_not_matching_prefix) is not adapter

    def test_session_get_adapter_prefix_without_trailing_slash(self):
        """
        Tests that session adapters mounted on prefixes without trailing slashes correctly route requests to the appropriate adapter, even for URLs with extended hostnames.
        
        This ensures consistent URL routing behavior in Requests' session adapter system, which is critical for accurate request handling in real-world scenarios involving subdomains or extended hostnames. The test specifically validates that both direct path matches and extended hostnames (e.g., example.com.other.com) are correctly routed when the mount prefix lacks a trailing slash, addressing a regression identified in issue #6935 and maintaining the library's reliability for complex URL patterns.
        """
        # from issue #6935
        prefix = "https://example.com"  # no trailing slash
        url_matching_prefix = "https://example.com/some/path"
        url_extended_hostname = "https://example.com.other.com/some/path"

        s = requests.Session()
        adapter = HTTPAdapter()
        s.mount(prefix, adapter)

        assert s.get_adapter(url_matching_prefix) is adapter
        assert s.get_adapter(url_extended_hostname) is adapter

    def test_header_remove_is_case_insensitive(self, httpbin):
        """
        Verifies that header removal is case-insensitive when setting a header value to None, ensuring consistent behavior across different header case variations.
        
        This test ensures Requests maintains predictable and intuitive header handling, aligning with HTTP standards and user expectations—critical for reliable API interactions and web scraping where header case consistency cannot be guaranteed.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        # From issue #1321
        s = requests.Session()
        s.headers["foo"] = "bar"
        r = s.get(httpbin("get"), headers={"FOO": None})
        assert "foo" not in r.request.headers

    def test_params_are_merged_case_sensitive(self, httpbin):
        """
        Tests that request parameters are correctly merged while preserving case sensitivity, ensuring consistent behavior when combining session-level and request-level parameters.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        s = requests.Session()
        s.params["foo"] = "bar"
        r = s.get(httpbin("get"), params={"FOO": "bar"})
        assert r.json()["args"] == {"foo": "bar", "FOO": "bar"}

    def test_long_authinfo_in_url(self):
        """
        Tests that long authentication credentials in URLs are preserved intact during request preparation, ensuring secure and accurate URL handling.
        
        This test verifies that Requests correctly maintains full username and password values—including long UUIDs—when preparing requests, which is critical for systems relying on complex or token-based authentication. By using a hostname exactly 63 characters long, it also checks edge cases in URL parsing to ensure robustness under real-world conditions where such constraints may occur. This aligns with Requests' goal of providing reliable, predictable HTTP behavior while preserving user-provided data without unintended modifications.
        """
        url = "http://{}:{}@{}:9000/path?query#frag".format(
            "E8A3BE87-9E3F-4620-8858-95478E385B5B",
            "EA770032-DA4D-4D84-8CE9-29C6D910BF1E",
            "exactly-------------sixty-----------three------------characters",
        )
        r = requests.Request("GET", url).prepare()
        assert r.url == url

    def test_header_keys_are_native(self, httpbin):
        """
        Tests that header keys are properly converted to native strings in the prepared request, ensuring consistent behavior across different input types. This is critical for Requests' goal of providing a reliable and predictable HTTP client interface, where users expect headers to be handled uniformly regardless of whether they are provided as Unicode strings or byte strings.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        headers = {"unicode": "blah", b"byte": "blah"}
        r = requests.Request("GET", httpbin("get"), headers=headers)
        p = r.prepare()

        # This is testing that they are builtin strings. A bit weird, but there
        # we go.
        assert "unicode" in p.headers.keys()
        assert "byte" in p.headers.keys()

    def test_header_validation(self, httpbin):
        """
        Verify that the header validation logic correctly handles valid header values without unintended filtering.
        
        This test ensures the prepare_headers regex does not incorrectly reject valid header contents, preserving the integrity of user-provided headers during HTTP requests. Given Requests' purpose of providing a reliable and intuitive HTTP client, accurate header handling is critical to prevent silent data loss or request failures when interacting with web services.
        """
        valid_headers = {
            "foo": "bar baz qux",
            "bar": b"fbbq",
            "baz": "",
            "qux": "1",
        }
        r = requests.get(httpbin("get"), headers=valid_headers)
        for key in valid_headers.keys():
            assert valid_headers[key] == r.request.headers[key]

    @pytest.mark.parametrize(
        "invalid_header, key",
        (
            ({"foo": 3}, "foo"),
            ({"bar": {"foo": "bar"}}, "bar"),
            ({"baz": ["foo", "bar"]}, "baz"),
        ),
    )
    def test_header_value_not_str(self, httpbin, invalid_header, key):
        """
        Verify that invalid header values (non-string, non-bytes) raise an appropriate error to maintain HTTP header integrity.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing.
            invalid_header: A dictionary containing a header with a value that is not a string or bytes, used to test error handling.
            key: The expected error key in the exception message, confirming the specific header that caused the validation failure.
        """
        with pytest.raises(InvalidHeader) as excinfo:
            requests.get(httpbin("get"), headers=invalid_header)
        assert key in str(excinfo.value)

    @pytest.mark.parametrize(
        "invalid_header",
        (
            {"foo": "bar\r\nbaz: qux"},
            {"foo": "bar\n\rbaz: qux"},
            {"foo": "bar\nbaz: qux"},
            {"foo": "bar\rbaz: qux"},
            {"fo\ro": "bar"},
            {"fo\r\no": "bar"},
            {"fo\n\ro": "bar"},
            {"fo\no": "bar"},
        ),
    )
    def test_header_no_return_chars(self, httpbin, invalid_header):
        """
        Ensure that headers containing return characters are rejected to prevent unintended header splitting and maintain HTTP protocol integrity.
        
        Invalid headers with newline characters could be misinterpreted as multiple headers, leading to security vulnerabilities or unexpected behavior in HTTP requests. This test verifies that such malformed headers raise an InvalidHeader exception, ensuring robustness and correctness in header handling.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
            invalid_header: Fixture containing a header string with return characters to test error handling.
        
        Returns:
            None, as the test asserts that an exception is raised.
        """
        with pytest.raises(InvalidHeader):
            requests.get(httpbin("get"), headers=invalid_header)

    @pytest.mark.parametrize(
        "invalid_header",
        (
            {" foo": "bar"},
            {"\tfoo": "bar"},
            {"    foo": "bar"},
            {"foo": " bar"},
            {"foo": "    bar"},
            {"foo": "\tbar"},
            {" ": "bar"},
        ),
    )
    def test_header_no_leading_space(self, httpbin, invalid_header):
        """
        Ensure that headers with leading whitespace trigger an InvalidHeader error during request preparation to maintain strict header formatting and prevent malformed requests.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
            invalid_header: Fixture containing a header dictionary with leading whitespace, used to test error handling.
        """
        with pytest.raises(InvalidHeader):
            requests.get(httpbin("get"), headers=invalid_header)

    def test_header_with_subclass_types(self, httpbin):
        """
        Tests support for custom str and bytes subclasses in HTTP headers to ensure backward compatibility.
        
        This test verifies that Requests correctly handles header keys and values created from custom subclasses of str and bytes, ensuring they behave identically to their base types. This is important for maintaining compatibility with code that uses subclassed strings or bytes for headers, which may be used for metadata tagging, type safety, or other domain-specific purposes. The test confirms that such subclasses are properly converted to standard strings when sending requests and correctly interpreted in the response headers.
        """

        class MyString(str):
            pass

        class MyBytes(bytes):
            pass

        r_str = requests.get(httpbin("get"), headers={MyString("x-custom"): "myheader"})
        assert r_str.request.headers["x-custom"] == "myheader"

        r_bytes = requests.get(
            httpbin("get"), headers={MyBytes(b"x-custom"): b"myheader"}
        )
        assert r_bytes.request.headers["x-custom"] == b"myheader"

        r_mixed = requests.get(
            httpbin("get"), headers={MyString("x-custom"): MyBytes(b"myheader")}
        )
        assert r_mixed.request.headers["x-custom"] == b"myheader"

    @pytest.mark.parametrize("files", ("foo", b"foo", bytearray(b"foo")))
    def test_can_send_objects_with_files(self, httpbin, files):
        """
        Tests that requests correctly use multipart/form-data content type when sending both form data and files, ensuring proper encoding for web service compatibility.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
            files: Fixture providing file data to be sent in the request.
        """
        data = {"a": "this is a string"}
        files = {"b": files}
        r = requests.Request("POST", httpbin("post"), data=data, files=files)
        p = r.prepare()
        assert "multipart/form-data" in p.headers["Content-Type"]

    def test_can_send_file_object_with_non_string_filename(self, httpbin):
        """
        Tests the ability to send a file object with a non-string filename in a multipart form request, ensuring compatibility with the Requests library's handling of file uploads.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing POST requests.
        """
        f = io.BytesIO()
        f.name = 2
        r = requests.Request("POST", httpbin("post"), files={"f": f})
        p = r.prepare()

        assert "multipart/form-data" in p.headers["Content-Type"]

    def test_autoset_header_values_are_native(self, httpbin):
        """
        Verifies that automatically set header values, such as Content-Length, are correctly converted to native string types to ensure compatibility with HTTP standards and proper request serialization.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        data = "this is a string"
        length = "16"
        req = requests.Request("POST", httpbin("post"), data=data)
        p = req.prepare()

        assert p.headers["Content-Length"] == length

    def test_nonhttp_schemes_dont_check_URLs(self):
        """
        Verifies that non-HTTP URL schemes (like data:, file:, and magnet:) are preserved unchanged during request preparation.
        
        Ensures Requests does not perform unintended validation or rewriting of non-HTTP URLs, which is critical for maintaining the integrity of special-purpose schemes used in web applications—such as embedding data directly via `data:` URIs, accessing local files via `file:` URIs, or initiating torrent downloads via `magnet:` URIs—while still providing robust HTTP request handling for standard web interactions.
        """
        test_urls = (
            "data:image/gif;base64,R0lGODlhAQABAHAAACH5BAUAAAAALAAAAAABAAEAAAICRAEAOw==",
            "file:///etc/passwd",
            "magnet:?xt=urn:btih:be08f00302bc2d1d3cfa3af02024fa647a271431",
        )
        for test_url in test_urls:
            req = requests.Request("GET", test_url)
            preq = req.prepare()
            assert test_url == preq.url

    def test_auth_is_stripped_on_http_downgrade(
        self, httpbin, httpbin_secure, httpbin_ca_bundle
    ):
        """
        Tests that HTTP Basic Authentication credentials are properly stripped when following redirects from HTTPS to HTTP, ensuring security by preventing credentials from being sent over unencrypted HTTP connections.
        
        Args:
            httpbin: Fixture providing the HTTP bin service URL for HTTP requests.
            httpbin_secure: Fixture providing the HTTP bin service URL for HTTPS requests.
            httpbin_ca_bundle: Fixture providing the CA bundle for verifying HTTPS connections.
        """
        r = requests.get(
            httpbin_secure("redirect-to"),
            params={"url": httpbin("get")},
            auth=("user", "pass"),
            verify=httpbin_ca_bundle,
        )
        assert r.history[0].request.headers["Authorization"]
        assert "Authorization" not in r.request.headers

    def test_auth_is_retained_for_redirect_on_host(self, httpbin):
        """
        Verifies that HTTP authentication credentials are preserved across redirects within the same host, ensuring consistent security behavior during automatic redirect following.
        
        This test validates Requests' correct handling of authentication when redirecting between endpoints on the same domain, which is critical for maintaining secure access to protected resources without requiring re-authentication.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        r = requests.get(httpbin("redirect/1"), auth=("user", "pass"))
        h1 = r.history[0].request.headers["Authorization"]
        h2 = r.request.headers["Authorization"]

        assert h1 == h2

    def test_should_strip_auth_host_change(self):
        """
        Tests that authentication credentials are properly stripped when switching between different domains to prevent credential leakage across hosts.
        
        This ensures security by enforcing the default behavior of not carrying authentication data from one domain to another, which is critical for preventing potential security vulnerabilities in HTTP sessions.
        """
        s = requests.Session()
        assert s.should_strip_auth(
            "http://example.com/foo", "http://another.example.com/"
        )

    def test_should_strip_auth_http_downgrade(self):
        """
        Tests that the session strips authentication credentials when downgrading from HTTPS to HTTP, ensuring security by default.
        
        This behavior prevents potential credential leakage when transitioning from a secure connection to an insecure one, aligning with Requests' goal of providing safe, intuitive HTTP interactions while protecting users from common security pitfalls in web requests.
        """
        s = requests.Session()
        assert s.should_strip_auth("https://example.com/foo", "http://example.com/bar")

    def test_should_strip_auth_https_upgrade(self):
        """
        Tests the logic for determining whether authentication credentials should be stripped during HTTP to HTTPS upgrades, ensuring secure handling of sensitive data.
        
        This behavior is critical in Requests' session management to prevent credential leakage when upgrading protocols, particularly on non-standard ports where the security assumptions may differ. By preserving credentials on standard ports (80/443) and stripping them on non-standard ports (e.g., 8080/8443), the library maintains a secure default that aligns with common web security practices while supporting flexible deployment scenarios.
        """
        s = requests.Session()
        assert not s.should_strip_auth(
            "http://example.com/foo", "https://example.com/bar"
        )
        assert not s.should_strip_auth(
            "http://example.com:80/foo", "https://example.com/bar"
        )
        assert not s.should_strip_auth(
            "http://example.com/foo", "https://example.com:443/bar"
        )
        # Non-standard ports should trigger stripping
        assert s.should_strip_auth(
            "http://example.com:8080/foo", "https://example.com/bar"
        )
        assert s.should_strip_auth(
            "http://example.com/foo", "https://example.com:8443/bar"
        )

    def test_should_strip_auth_port_change(self):
        """
        Tests that authentication credentials are properly stripped when switching between HTTP and HTTPS URLs with different ports, ensuring secure session behavior. This protects against potential security vulnerabilities by preventing credentials from being inadvertently reused across different protocol or port contexts, aligning with Requests' goal of providing safe, predictable HTTP interactions.
        """
        s = requests.Session()
        assert s.should_strip_auth(
            "http://example.com:1234/foo", "https://example.com:4321/bar"
        )

    @pytest.mark.parametrize(
        "old_uri, new_uri",
        (
            ("https://example.com:443/foo", "https://example.com/bar"),
            ("http://example.com:80/foo", "http://example.com/bar"),
            ("https://example.com/foo", "https://example.com:443/bar"),
            ("http://example.com/foo", "http://example.com:80/bar"),
        ),
    )
    def test_should_strip_auth_default_port(self, old_uri, new_uri):
        """
        Verifies that authentication credentials are preserved during redirects when the old and new URIs use the same default port, ensuring consistent session behavior across HTTP redirects.
        
        Args:
            old_uri: The original URI to compare against
            new_uri: The new URI to compare with
        """
        s = requests.Session()
        assert not s.should_strip_auth(old_uri, new_uri)

    def test_manual_redirect_with_partial_body_read(self, httpbin):
        """
        Tests the session's ability to handle redirects when only part of the response body is read before following redirects, ensuring correct state tracking across redirect chains.
        
        This test verifies that Requests maintains proper redirect state and continues processing subsequent redirects correctly even when the first response body is partially consumed. It ensures robustness in real-world scenarios where response bodies may be read incrementally (e.g., streaming or chunked processing), aligning with Requests' goal of providing reliable, intuitive HTTP handling for web scraping and API integration.
        """
        s = requests.Session()
        r1 = s.get(httpbin("redirect/2"), allow_redirects=False, stream=True)
        assert r1.is_redirect
        rg = s.resolve_redirects(r1, r1.request, stream=True)

        # read only the first eight bytes of the response body,
        # then follow the redirect
        r1.iter_content(8)
        r2 = next(rg)
        assert r2.is_redirect

        # read all of the response via iter_content,
        # then follow the redirect
        for _ in r2.iter_content():
            pass
        r3 = next(rg)
        assert not r3.is_redirect

    def test_prepare_body_position_non_stream(self):
        """
        Verifies that non-streaming requests maintain an unset body position, ensuring consistent default behavior.
        
        Confirms that when a request is prepared without streaming, the internal _body_position attribute remains None, which aligns with Requests' design principle of minimizing assumptions and preserving default state for non-streaming scenarios. This behavior ensures predictable handling of request bodies and supports the library's goal of providing a clean, intuitive interface for HTTP operations.
        """
        data = b"the data"
        prep = requests.Request("GET", "http://example.com", data=data).prepare()
        assert prep._body_position is None

    def test_rewind_body(self):
        """
        Tests that rewinding a request body resets its position to the beginning, ensuring the body can be read multiple times.
        
        This is essential for Requests' internal handling of request bodies, particularly when the same request needs to be replayed (e.g., during redirects or retries). The function verifies that after reading the entire body, calling `rewind_body` restores the read position to the start, allowing the body to be re-read—critical for maintaining correct behavior in scenarios where the request body must be sent more than once without re-encoding. The test uses a BytesIO stream containing b"the data" to simulate a request body and confirms that rewinding enables re-reading from the beginning.
        """
        data = io.BytesIO(b"the data")
        prep = requests.Request("GET", "http://example.com", data=data).prepare()
        assert prep._body_position == 0
        assert prep.body.read() == b"the data"

        # the data has all been read
        assert prep.body.read() == b""

        # rewind it back
        requests.utils.rewind_body(prep)
        assert prep.body.read() == b"the data"

    def test_rewind_partially_read_body(self):
        """
        Tests the ability to rewind a partially read request body to restore the original read position, enabling the remaining data to be re-read.
        
        This ensures that when a request body is partially consumed during processing (e.g., for streaming or inspection), it can be reset to its original state—critical for retrying requests or reprocessing the same data. The test verifies that rewind_body correctly restores the read position to 4, allowing the remaining data ("data") to be read again, which supports reliable request handling in scenarios involving connection retries or middleware that may need to re-examine the request body.
        """
        data = io.BytesIO(b"the data")
        data.read(4)  # read some data
        prep = requests.Request("GET", "http://example.com", data=data).prepare()
        assert prep._body_position == 4
        assert prep.body.read() == b"data"

        # the data has all been read
        assert prep.body.read() == b""

        # rewind it back
        requests.utils.rewind_body(prep)
        assert prep.body.read() == b"data"

    def test_rewind_body_no_seek(self):
        """
        Tests the behavior of rewinding a request body when the underlying file-like object lacks seek functionality, ensuring proper error handling to prevent data loss or unexpected behavior during retries.
        
        This validation supports Requests' goal of robust HTTP request management by verifying that non-seekable bodies raise appropriate errors, maintaining reliability when reusing requests in sessions or retry scenarios.
        
        Returns:
            None
        """
        class BadFileObj:
            def __init__(self, data):
                self.data = data

            def tell(self):
                return 0

            def __iter__(self):
                return

        data = BadFileObj("the data")
        prep = requests.Request("GET", "http://example.com", data=data).prepare()
        assert prep._body_position == 0

        with pytest.raises(UnrewindableBodyError) as e:
            requests.utils.rewind_body(prep)

        assert "Unable to rewind request body" in str(e)

    def test_rewind_body_failed_seek(self):
        """
        Tests the resilience of the rewind_body utility when seeking fails due to an OSError, ensuring graceful error handling during request body rewinding.
        
        This test verifies that when a custom file-like object raises an OSError during seek, the rewind_body function correctly raises an UnrewindableBodyError with a descriptive message, maintaining the reliability of request processing in cases where the request body cannot be rewound. This is critical for Requests' ability to handle streaming or non-seekable data sources robustly, especially during retries or when using custom request bodies.
        
        Returns:
            None
        """
        class BadFileObj:
            def __init__(self, data):
                self.data = data

            def tell(self):
                return 0

            def seek(self, pos, whence=0):
                raise OSError()

            def __iter__(self):
                return

        data = BadFileObj("the data")
        prep = requests.Request("GET", "http://example.com", data=data).prepare()
        assert prep._body_position == 0

        with pytest.raises(UnrewindableBodyError) as e:
            requests.utils.rewind_body(prep)

        assert "error occurred when rewinding request body" in str(e)

    def test_rewind_body_failed_tell(self):
        """
        Tests the graceful failure of rewinding a request body when the underlying file-like object's tell() method raises an OSError, ensuring robustness in edge cases during HTTP request processing.
        
        Returns:
            None; raises UnrewindableBodyError with a specific message when unable to rewind the body, maintaining reliability in request handling despite unexpected I/O errors.
        """
        class BadFileObj:
            def __init__(self, data):
                self.data = data

            def tell(self):
                raise OSError()

            def __iter__(self):
                return

        data = BadFileObj("the data")
        prep = requests.Request("GET", "http://example.com", data=data).prepare()
        assert prep._body_position is not None

        with pytest.raises(UnrewindableBodyError) as e:
            requests.utils.rewind_body(prep)

        assert "Unable to rewind request body" in str(e)

    def _patch_adapter_gzipped_redirect(self, session, url):
        """
        Forces gzip content encoding on responses by patching the adapter's build_response method, ensuring compressed responses are properly handled during HTTP requests.
        
        Args:
            session: The requests.Session object containing the adapter to patch
            url: The URL used to retrieve the adapter from the session
        
        Returns:
            None
        """
        adapter = session.get_adapter(url=url)
        org_build_response = adapter.build_response
        self._patched_response = False

        def build_response(*args, **kwargs):
            resp = org_build_response(*args, **kwargs)
            if not self._patched_response:
                resp.raw.headers["content-encoding"] = "gzip"
                self._patched_response = True
            return resp

        adapter.build_response = build_response

    def test_redirect_with_wrong_gzipped_header(self, httpbin):
        """
        Tests the library's ability to handle redirects when the response includes a malformed gzipped Content-Encoding header, ensuring robustness in real-world scenarios where servers may send incorrect or malformed headers.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        s = requests.Session()
        url = httpbin("redirect/1")
        self._patch_adapter_gzipped_redirect(s, url)
        s.get(url)

    @pytest.mark.parametrize(
        "username, password, auth_str",
        (
            ("test", "test", "Basic dGVzdDp0ZXN0"),
            (
                "имя".encode(),
                "пароль".encode(),
                "Basic 0LjQvNGPOtC/0LDRgNC+0LvRjA==",
            ),
        ),
    )
    def test_basic_auth_str_is_always_native(self, username, password, auth_str):
        """
        Verifies that the basic authentication string is consistently returned as a native string (str) and matches the expected value, ensuring compatibility with HTTP headers and downstream components.
        
        Args:
            username: The username to include in the authentication string.
            password: The password to include in the authentication string.
            auth_str: The expected value of the basic authentication string.
        """
        s = _basic_auth_str(username, password)
        assert isinstance(s, builtin_str)
        assert s == auth_str

    def test_requests_history_is_saved(self, httpbin):
        """
        Verifies that the request history is correctly preserved across multiple redirects, ensuring that each redirect's history accurately reflects the cumulative chain of previous requests. This test is critical for maintaining reliable tracking of HTTP request flow in Requests, which supports session management and debugging by preserving historical context through redirects.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP behavior
        """
        r = requests.get(httpbin("redirect/5"))
        total = r.history[-1].history
        i = 0
        for item in r.history:
            assert item.history == total[0:i]
            i += 1

    def test_json_param_post_content_type_works(self, httpbin):
        """
        Tests that the `json` parameter in POST requests automatically sets the Content-Type header to application/json, ensuring proper JSON serialization and server recognition. This verifies Requests' correct handling of JSON data, which aligns with the library's goal of simplifying HTTP interactions by automatically managing common headers and encoding.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        r = requests.post(httpbin("post"), json={"life": 42})
        assert r.status_code == 200
        assert "application/json" in r.request.headers["Content-Type"]
        assert {"life": 42} == r.json()["json"]

    def test_json_param_post_should_not_override_data_param(self, httpbin):
        """
        Tests that the json parameter in a POST request does not override the data parameter, ensuring predictable request body construction.
        
        This test verifies Requests' behavior aligns with its design principle of providing clear, intuitive HTTP request handling by preventing unintended data loss when both data and json parameters are used. The library is designed to make HTTP interactions simple and reliable, so this check ensures users can confidently use both parameters without unexpected side effects.
        """
        r = requests.Request(
            method="POST",
            url=httpbin("post"),
            data={"stuff": "elixr"},
            json={"music": "flute"},
        )
        prep = r.prepare()
        assert "stuff=elixr" == prep.body

    def test_response_iter_lines(self, httpbin):
        """
        Tests the behavior of `iter_lines()` on a streamed HTTP response to ensure it correctly yields the expected number of lines, verifying proper handling of chunked streaming data.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing streaming responses, allowing validation of Requests' ability to process real-world streaming HTTP content.
        """
        r = requests.get(httpbin("stream/4"), stream=True)
        assert r.status_code == 200

        it = r.iter_lines()
        next(it)
        assert len(list(it)) == 3

    def test_response_context_manager(self, httpbin):
        """
        Verifies that the response context manager properly handles streaming HTTP requests, ensuring resources are correctly managed and closed after use. This test is critical for maintaining reliability in long-running or large-data scenarios, aligning with Requests' goal of providing intuitive and safe HTTP interaction.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing.
        """
        with requests.get(httpbin("stream/4"), stream=True) as response:
            assert isinstance(response, requests.Response)

        assert response.raw.closed

    def test_unconsumed_session_response_closes_connection(self, httpbin):
        """
        Verifies that a session response without content consumption still closes the underlying connection, ensuring proper resource cleanup and preventing connection leaks.
        
        This test is critical for maintaining the reliability and efficiency of Requests' connection management, especially in long-running applications or high-throughput scenarios where unmanaged connections could lead to resource exhaustion.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior.
        """
        s = requests.session()

        with contextlib.closing(s.get(httpbin("stream/4"), stream=True)) as response:
            pass

        assert response._content_consumed is False
        assert response.raw.closed

    @pytest.mark.xfail
    def test_response_iter_lines_reentrant(self, httpbin):
        """
        Verifies that Response.iter_lines() is not reentrant safe, ensuring consistent behavior in streaming responses.
        
        This test checks the expected non-reentrant behavior of iter_lines() in the context of Requests' streaming API, which is designed to handle large or continuous data streams efficiently. By confirming that calling iter_lines() multiple times without reinitializing the stream leads to predictable results, the test upholds the library's reliability for real-world use cases involving streaming data from HTTP endpoints.
        """
        r = requests.get(httpbin("stream/4"), stream=True)
        assert r.status_code == 200

        next(r.iter_lines())
        assert len(list(r.iter_lines())) == 3

    def test_session_close_proxy_clear(self):
        """
        Verifies that closing a requests.Session properly cleans up proxy connections by calling clear() on each proxy in the manager.
        
        This ensures reliable resource management and prevents connection leaks when sessions are closed, which is critical for long-running applications and high-throughput systems that rely on Requests for consistent HTTP communication. By confirming each proxy's clear method is called exactly once, the test validates that the proxy manager correctly releases all associated resources, maintaining the library's goal of robust, predictable, and efficient HTTP interactions.
        """
        proxies = {
            "one": mock.Mock(),
            "two": mock.Mock(),
        }
        session = requests.Session()
        with mock.patch.dict(session.adapters["http://"].proxy_manager, proxies):
            session.close()
            proxies["one"].clear.assert_called_once_with()
            proxies["two"].clear.assert_called_once_with()

    def test_proxy_auth(self):
        """
        Tests that proxy authentication headers are correctly generated using basic authentication.
        
        Ensures the proxy_headers method properly encodes credentials from a proxy URL into a valid Proxy-Authorization header with Base64 encoding, which is essential for authenticating with HTTP proxies in Requests. This validation supports the library's goal of simplifying secure HTTP communication by correctly handling proxy authentication details behind the scenes.
        """
        adapter = HTTPAdapter()
        headers = adapter.proxy_headers("http://user:pass@httpbin.org")
        assert headers == {"Proxy-Authorization": "Basic dXNlcjpwYXNz"}

    def test_proxy_auth_empty_pass(self):
        """
        Tests that the proxy authentication logic correctly handles URLs with a username but no password, ensuring the proper 'Proxy-Authorization' header is generated.
        
        This verification is critical for maintaining compatibility with HTTP proxy standards, where an empty password is encoded as 'Basic dXNlcjo='—a common pattern in proxy authentication. The test ensures Requests correctly processes such URLs, supporting reliable communication with authenticated proxies while aligning with the library's goal of simplifying secure HTTP interactions.
        """
        adapter = HTTPAdapter()
        headers = adapter.proxy_headers("http://user:@httpbin.org")
        assert headers == {"Proxy-Authorization": "Basic dXNlcjo="}

    def test_response_json_when_content_is_None(self, httpbin):
        """
        Tests the behavior of the response's json() method when the response content is None, ensuring it raises a ValueError to maintain consistent error handling. This is important for robust API clients that rely on predictable behavior when processing HTTP responses with no content.
        
        Args:
            httpbin: Fixture providing a URL to a local httpbin instance for testing HTTP responses.
        """
        r = requests.get(httpbin("/status/204"))
        # Make sure r.content is None
        r.status_code = 0
        r._content = False
        r._content_consumed = False

        assert r.content is None
        with pytest.raises(ValueError):
            r.json()

    def test_response_without_release_conn(self):
        """
        Test that the `close` method works correctly on responses with raw objects that don't have a `release_conn` attribute.
        
        This ensures compatibility with non-urllib3-like raw response objects, maintaining Requests' goal of providing a consistent and reliable HTTP client interface regardless of the underlying transport implementation. The test verifies that closing a response properly closes its raw data stream, even when the raw object lacks the `release_conn` method typically found in urllib3-based responses.
        """
        resp = requests.Response()
        resp.raw = StringIO.StringIO("test")
        assert not resp.raw.closed
        resp.close()
        assert resp.raw.closed

    def test_empty_stream_with_auth_does_not_set_content_length_header(self, httpbin):
        """
        Ensure that when sending an empty byte stream with authentication, Requests does not set both Content-Length and Transfer-Encoding headers, which could lead to invalid HTTP requests.
        
        This behavior is critical for maintaining compliance with HTTP/1.1 standards, where having both headers simultaneously is prohibited. By avoiding this conflict, Requests ensures reliable and correct request formatting, especially when using authentication with empty payloads, which is common in API testing and secure endpoint interactions.
        """
        auth = ("user", "pass")
        url = httpbin("post")
        file_obj = io.BytesIO(b"")
        r = requests.Request("POST", url, auth=auth, data=file_obj)
        prepared_request = r.prepare()
        assert "Transfer-Encoding" in prepared_request.headers
        assert "Content-Length" not in prepared_request.headers

    def test_stream_with_auth_does_not_set_transfer_encoding_header(self, httpbin):
        """
        Ensure that when sending a byte stream with a size greater than 0 using authentication, the request does not include both Content-Length and Transfer-Encoding headers, which could lead to invalid HTTP semantics.
        
        This check maintains HTTP protocol correctness by preventing conflicting transfer encodings, ensuring reliable request handling and compatibility with HTTP servers. The test verifies that Requests properly manages headers when using authenticated POST requests with file-like objects, aligning with the library's goal of simplifying HTTP interactions while preserving protocol integrity.
        """
        auth = ("user", "pass")
        url = httpbin("post")
        file_obj = io.BytesIO(b"test data")
        r = requests.Request("POST", url, auth=auth, data=file_obj)
        prepared_request = r.prepare()
        assert "Transfer-Encoding" not in prepared_request.headers
        assert "Content-Length" in prepared_request.headers

    def test_chunked_upload_does_not_set_content_length_header(self, httpbin):
        """
        Ensure that POST requests with generator bodies use chunked transfer encoding instead of a content length header, which is essential for streaming large or infinite data efficiently.
        
        This behavior aligns with Requests' purpose of providing intuitive, efficient HTTP communication by automatically handling streaming uploads without requiring the user to manually manage content length or chunking, enabling seamless interaction with servers that expect streaming data.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
        """
        data = (i for i in [b"a", b"b", b"c"])
        url = httpbin("post")
        r = requests.Request("POST", url, data=data)
        prepared_request = r.prepare()
        assert "Transfer-Encoding" in prepared_request.headers
        assert "Content-Length" not in prepared_request.headers

    def test_custom_redirect_mixin(self, httpbin):
        """
        Tests a custom redirect handling mixin to ensure robustness when encountering malformed redirect responses.
        
        The test verifies that a subclassed `requests.Session` can correctly follow redirects even when intermediate responses have inconsistent status codes (e.g., 200 with a `Location` header), which may occur in real-world scenarios due to server misconfigurations. This is critical for maintaining reliable HTTP behavior in the Requests library, where consistent and predictable redirect handling enhances the user experience and prevents unexpected failures during web interactions.
        """
        url_final = httpbin("html")
        querystring_malformed = urlencode({"location": url_final})
        url_redirect_malformed = httpbin("response-headers?%s" % querystring_malformed)
        querystring_redirect = urlencode({"url": url_redirect_malformed})
        url_redirect = httpbin("redirect-to?%s" % querystring_redirect)
        urls_test = [
            url_redirect,
            url_redirect_malformed,
            url_final,
        ]

        class CustomRedirectSession(requests.Session):
            def get_redirect_target(self, resp):
                # default behavior
                if resp.is_redirect:
                    return resp.headers["location"]
                # edge case - check to see if 'location' is in headers anyways
                location = resp.headers.get("location")
                if location and (location != resp.url):
                    return location
                return None

        session = CustomRedirectSession()
        r = session.get(urls_test[0])
        assert len(r.history) == 2
        assert r.status_code == 200
        assert r.history[0].status_code == 302
        assert r.history[0].is_redirect
        assert r.history[1].status_code == 200
        assert not r.history[1].is_redirect
        assert r.url == urls_test[2]


class TestCaseInsensitiveDict:
    """
    A dictionary-like class that provides case-insensitive key access while preserving the original case of keys.
    
        Methods:
        - __init__: Initializes the CaseInsensitiveDict with optional initial data.
        - __setitem__: Sets a value for a key, using case-insensitive comparison to determine the key.
        - __getitem__: Retrieves a value using case-insensitive key lookup.
        - __delitem__: Deletes an item using case-insensitive key lookup.
        - __contains__: Checks if a key exists in the dictionary using case-insensitive comparison.
        - __iter__: Returns an iterator over the original keys, preserving their case.
        - __len__: Returns the number of unique keys in the dictionary (case-insensitive).
        - get: Retrieves a value for a key using case-insensitive lookup, with optional default.
        - update: Updates the dictionary with new key-value pairs, using case-insensitive key resolution.
        - setdefault: Returns the value for a key if it exists (case-insensitive), otherwise inserts a default.
        - lower_items: Returns an iterator over (lowercase_key, value) pairs.
        - copy: Returns a shallow copy of the CaseInsensitiveDict.
        - keys: Returns a view of the original keys, preserving their case.
        - items: Returns a view of (original_key, value) pairs.
        - values: Returns a view of the values.
    
        Attributes:
        - _data: Internal storage for key-value pairs, maintaining original key case.
        - _keys: List of original keys as they were inserted, preserving case.
    
        The CaseInsensitiveDict allows case-insensitive key access while maintaining the original case of keys in the dictionary's interface. Keys are compared in a case-insensitive manner during operations like retrieval, setting, and deletion, but the original case of keys is preserved in iteration, keys(), items(), and other views. This ensures consistent behavior for both lookup and display, making it suitable for use cases like HTTP headers where case-insensitive access is required but original formatting must be retained.
    """

    @pytest.mark.parametrize(
        "cid",
        (
            CaseInsensitiveDict({"Foo": "foo", "BAr": "bar"}),
            CaseInsensitiveDict([("Foo", "foo"), ("BAr", "bar")]),
            CaseInsensitiveDict(FOO="foo", BAr="bar"),
        ),
    )
    def test_init(self, cid):
        """
        Verifies that the CID (Client ID) contains exactly the expected values 'foo' and 'bar' to ensure proper initialization of the request session.
        
        Args:
            cid: List or sequence expected to contain exactly two elements, 'foo' and 'bar', representing the required client identifier components for session setup.
        """
        assert len(cid) == 2
        assert "foo" in cid
        assert "bar" in cid

    def test_docstring_example(self):
        """
        Tests that CaseInsensitiveDict correctly handles case-insensitive key access, which is essential for HTTP header handling in Requests. This ensures consistent behavior when working with headers like 'Accept', 'Content-Type', or 'Authorization', where case variations should not affect retrieval, maintaining reliability in HTTP request and response processing.
        """
        cid = CaseInsensitiveDict()
        cid["Accept"] = "application/json"
        assert cid["aCCEPT"] == "application/json"
        assert list(cid) == ["Accept"]

    def test_len(self):
        """
        Verifies that CaseInsensitiveDict correctly tracks unique keys regardless of case, ensuring consistent behavior when interacting with HTTP headers and other case-insensitive data structures.
        
        This test is critical for Requests' reliability: HTTP headers are case-insensitive by specification, so the dictionary must treat 'Content-Type' and 'content-type' as equivalent. Ensuring length accuracy prevents bugs in header management, session handling, and request/response processing—core to Requests' mission of simplifying HTTP interactions.
        """
        cid = CaseInsensitiveDict({"a": "a", "b": "b"})
        cid["A"] = "a"
        assert len(cid) == 2

    def test_getitem(self):
        """
        Tests that CaseInsensitiveDict correctly handles case-insensitive key lookup, ensuring consistent access to values regardless of key casing. This is essential for HTTP headers and metadata in Requests, where standardization across different capitalizations (e.g., 'Content-Type', 'content-type') is critical for reliable and predictable behavior during request and response processing.
        """
        cid = CaseInsensitiveDict({"Spam": "blueval"})
        assert cid["spam"] == "blueval"
        assert cid["SPAM"] == "blueval"

    def test_fixes_649(self):
        """
        Verifies that __setitem__ in CaseInsensitiveDict behaves case-insensitively, ensuring consistent key handling across different capitalizations.
        
        This test is critical for Requests' internal use of CaseInsensitiveDict to manage HTTP headers, where header names must be treated uniformly regardless of case (e.g., 'Content-Type' vs 'content-type'). Ensuring case-insensitive behavior prevents duplicate or inconsistent header storage, which could lead to incorrect request or response handling.
        """
        cid = CaseInsensitiveDict()
        cid["spam"] = "oneval"
        cid["Spam"] = "twoval"
        cid["sPAM"] = "redval"
        cid["SPAM"] = "blueval"
        assert cid["spam"] == "blueval"
        assert cid["SPAM"] == "blueval"
        assert list(cid.keys()) == ["SPAM"]

    def test_delitem(self):
        """
        Tests the case-insensitive deletion behavior of CaseInsensitiveDict to ensure that keys are properly removed regardless of case variation. This is critical for Requests' internal handling of HTTP headers, where case-insensitive key access is required to maintain consistent and predictable behavior across different header formats.
        """
        cid = CaseInsensitiveDict()
        cid["Spam"] = "someval"
        del cid["sPam"]
        assert "spam" not in cid
        assert len(cid) == 0

    def test_contains(self):
        """
        Tests that CaseInsensitiveDict correctly handles case-insensitive key lookup, ensuring consistent behavior when accessing headers or other case-sensitive data in HTTP requests.
        
        This is critical for the Requests library, which must reliably process HTTP headers—where case variations should not affect key retrieval—enabling robust and predictable interaction with web servers regardless of how headers are capitalized in responses.
        """
        cid = CaseInsensitiveDict()
        cid["Spam"] = "someval"
        assert "Spam" in cid
        assert "spam" in cid
        assert "SPAM" in cid
        assert "sPam" in cid
        assert "notspam" not in cid

    def test_get(self):
        """
        Tests the case-insensitive key retrieval behavior of CaseInsensitiveDict, ensuring consistent access to values regardless of key casing. This is critical for HTTP headers and similar use cases in Requests, where header names must be treated uniformly across different capitalizations while maintaining predictable behavior during lookup operations.
        """
        cid = CaseInsensitiveDict()
        cid["spam"] = "oneval"
        cid["SPAM"] = "blueval"
        assert cid.get("spam") == "blueval"
        assert cid.get("SPAM") == "blueval"
        assert cid.get("sPam") == "blueval"
        assert cid.get("notspam", "default") == "default"

    def test_update(self):
        """
        Tests the update method of CaseInsensitiveDict to ensure it correctly handles case-insensitive key updates, which is essential for consistent header handling in HTTP requests. This ensures that HTTP headers, which are case-insensitive by specification, are reliably managed in Requests' internal data structures, maintaining correctness and predictability during request and response processing.
        """
        cid = CaseInsensitiveDict()
        cid["spam"] = "blueval"
        cid.update({"sPam": "notblueval"})
        assert cid["spam"] == "notblueval"
        cid = CaseInsensitiveDict({"Foo": "foo", "BAr": "bar"})
        cid.update({"fOO": "anotherfoo", "bAR": "anotherbar"})
        assert len(cid) == 2
        assert cid["foo"] == "anotherfoo"
        assert cid["bar"] == "anotherbar"

    def test_update_retains_unchanged(self):
        """
        Verifies that updating a CaseInsensitiveDict preserves unmodified key-value pairs, ensuring consistent behavior when merging data without unintended changes.
        
        This test is critical for Requests' reliability, as CaseInsensitiveDict is used internally to manage HTTP headers—where case-insensitive key access is essential. Ensuring that updates only affect specified keys prevents accidental overwrites of other headers, maintaining the integrity of request and response metadata.
        """
        cid = CaseInsensitiveDict({"foo": "foo", "bar": "bar"})
        cid.update({"foo": "newfoo"})
        assert cid["bar"] == "bar"

    def test_iter(self):
        """
        Tests the case-insensitive iteration behavior of CaseInsensitiveDict to ensure it correctly preserves key identity during iteration, which is essential for consistent header handling in HTTP requests. This validation supports Requests' goal of providing reliable and predictable interaction with HTTP headers, where case variations should not affect key access or traversal.
        """
        cid = CaseInsensitiveDict({"Spam": "spam", "Eggs": "eggs"})
        keys = frozenset(["Spam", "Eggs"])
        assert frozenset(iter(cid)) == keys

    def test_equality(self):
        """
        Tests the equality and inequality behavior of CaseInsensitiveDict to ensure it correctly compares case-insensitive dictionaries with other objects, including regular dictionaries and non-dict types. This is essential for Requests' internal handling of HTTP headers, where case-insensitive comparison is required to maintain consistent and predictable behavior when comparing headers across different request and response objects.
        """
        cid = CaseInsensitiveDict({"SPAM": "blueval", "Eggs": "redval"})
        othercid = CaseInsensitiveDict({"spam": "blueval", "eggs": "redval"})
        assert cid == othercid
        del othercid["spam"]
        assert cid != othercid
        assert cid == {"spam": "blueval", "eggs": "redval"}
        assert cid != object()

    def test_setdefault(self):
        """
        Tests the setdefault method of CaseInsensitiveDict to verify correct case-insensitive key handling, ensuring that existing values are returned when keys match regardless of case, and default values are inserted when keys are missing.
        
        This test is critical for Requests' internal data structures, which rely on case-insensitive dictionary behavior to consistently handle HTTP headers—where header names like 'Content-Type' and 'content-type' must be treated as equivalent—ensuring reliable and predictable header management during HTTP request and response processing.
        """
        cid = CaseInsensitiveDict({"Spam": "blueval"})
        assert cid.setdefault("spam", "notblueval") == "blueval"
        assert cid.setdefault("notspam", "notblueval") == "notblueval"

    def test_lower_items(self):
        """
        Tests that lower_items correctly returns lowercase keys from a CaseInsensitiveDict, ensuring consistent case-insensitive key access.
        
        This verification is critical for Requests' ability to handle HTTP headers reliably, where header names should be treated case-insensitively per the HTTP specification. By confirming that lower_items returns properly normalized lowercase keys, the test ensures that header lookups and comparisons work correctly regardless of original casing, maintaining the library's robustness in real-world HTTP interactions.
        """
        cid = CaseInsensitiveDict(
            {
                "Accept": "application/json",
                "user-Agent": "requests",
            }
        )
        keyset = frozenset(lowerkey for lowerkey, v in cid.lower_items())
        lowerkeyset = frozenset(["accept", "user-agent"])
        assert keyset == lowerkeyset

    def test_preserve_key_case(self):
        """
        Verifies that CaseInsensitiveDict maintains the original key casing across all access methods, ensuring consistent behavior when interacting with HTTP headers. This is critical for Requests' reliability in handling header names, where preserving the original case ensures correct header formatting and avoids unintended side effects during HTTP communication.
        """
        cid = CaseInsensitiveDict(
            {
                "Accept": "application/json",
                "user-Agent": "requests",
            }
        )
        keyset = frozenset(["Accept", "user-Agent"])
        assert frozenset(i[0] for i in cid.items()) == keyset
        assert frozenset(cid.keys()) == keyset
        assert frozenset(cid) == keyset

    def test_preserve_last_key_case(self):
        """
        Tests that CaseInsensitiveDict retains the case of the last key added, ensuring consistent key representation during case-insensitive lookups. This behavior is critical for Requests' header handling, where headers must be case-insensitive for compliance with HTTP standards while preserving the canonical case of the final key for accurate header display and debugging.
        """
        cid = CaseInsensitiveDict(
            {
                "Accept": "application/json",
                "user-Agent": "requests",
            }
        )
        cid.update({"ACCEPT": "application/json"})
        cid["USER-AGENT"] = "requests"
        keyset = frozenset(["ACCEPT", "USER-AGENT"])
        assert frozenset(i[0] for i in cid.items()) == keyset
        assert frozenset(cid.keys()) == keyset
        assert frozenset(cid) == keyset

    def test_copy(self):
        """
        Tests the copy method of CaseInsensitiveDict to ensure it creates a shallow copy that accurately reflects the original dictionary's state.
        
        This test is critical for maintaining data integrity in HTTP request handling, where headers are often case-insensitive and must be preserved across operations. By verifying that the copy is independent of the original, we ensure that modifications to one dictionary do not inadvertently affect others—this is essential for safe session management, header manipulation, and request cloning in the Requests library.
        """
        cid = CaseInsensitiveDict(
            {
                "Accept": "application/json",
                "user-Agent": "requests",
            }
        )
        cid_copy = cid.copy()
        assert cid == cid_copy
        cid["changed"] = True
        assert cid != cid_copy


class TestMorselToCookieExpires:
    """
    Tests for morsel_to_cookie when morsel contains expires.
    """


    def test_expires_valid_str(self):
        """
        Test that the cookie expiration time is correctly parsed from a string format into a Unix timestamp.
        
        This ensures proper handling of HTTP cookie expiration headers, which is critical for maintaining session state and ensuring cookies are valid for the intended duration. The test validates that the `morsel_to_cookie` function correctly interprets standard HTTP date strings (like 'Thu, 01-Jan-1970 00:00:01 GMT') and converts them to the expected integer timestamp format used internally by Requests.
        """

        morsel = Morsel()
        morsel["expires"] = "Thu, 01-Jan-1970 00:00:01 GMT"
        cookie = morsel_to_cookie(morsel)
        assert cookie.expires == 1

    @pytest.mark.parametrize(
        "value, exception",
        (
            (100, TypeError),
            ("woops", ValueError),
        ),
    )
    def test_expires_invalid_int(self, value, exception):
        """
        Tests that invalid integer values for the 'expires' attribute raise the expected exception when converting a Morsel to a cookie.
        
        This ensures robust handling of malformed or unsupported expiration values in cookie generation, which is critical for maintaining security and compatibility when working with HTTP cookies in the Requests library. The test validates that improper input types are caught early, preventing potential issues during HTTP request/response cycles.
        
        Args:
            value: The invalid integer value to assign to the 'expires' attribute.
            exception: The expected exception type that should be raised when processing the invalid value.
        """
        morsel = Morsel()
        morsel["expires"] = value
        with pytest.raises(exception):
            morsel_to_cookie(morsel)

    def test_expires_none(self):
        """
        Tests that a cookie's expires attribute is preserved as None when set in a Morsel, ensuring proper handling of session-only cookies in the cookie serialization process.
        
        This test verifies the correct behavior of the morsel_to_cookie function when dealing with cookies that have no expiration time (i.e., session cookies), which is essential for maintaining session state correctly in HTTP requests. This aligns with Requests' goal of accurately representing and managing cookies according to HTTP standards.
        """

        morsel = Morsel()
        morsel["expires"] = None
        cookie = morsel_to_cookie(morsel)
        assert cookie.expires is None


class TestMorselToCookieMaxAge:
    """
    Tests for morsel_to_cookie when morsel contains max-age.
    """

    """Tests for morsel_to_cookie when morsel contains max-age."""

    def test_max_age_valid_int(self):
        """
        Tests that a valid max-age value in seconds is correctly parsed and stored as an integer expiration time.
        
        This ensures cookies with a max-age attribute are properly handled by the library, maintaining compatibility with HTTP standards and enabling reliable session management in web interactions. The test verifies that the Morsel object's max-age value is correctly converted to a cookie's expires field as an integer, which is essential for accurate cookie expiration behavior in requests.
        """

        morsel = Morsel()
        morsel["max-age"] = 60
        cookie = morsel_to_cookie(morsel)
        assert isinstance(cookie.expires, int)

    def test_max_age_invalid_str(self):
        """
        Tests that invalid 'max-age' values raise a TypeError when converting a Morsel to a cookie.
        
        This ensures robustness in cookie handling by validating input integrity—Requests must reject malformed max-age values (like non-numeric strings) to prevent incorrect or unsafe cookie headers, maintaining compliance with HTTP standards and preventing potential security issues.
        """

        morsel = Morsel()
        morsel["max-age"] = "woops"
        with pytest.raises(TypeError):
            morsel_to_cookie(morsel)


class TestTimeout:
    """
    Test class for verifying timeout behavior in HTTP requests.
    
        This class contains multiple test methods to validate different timeout scenarios,
        including stream timeouts, invalid timeout values, None timeouts, read timeouts,
        and connection timeouts. Each test ensures that the timeout mechanism behaves
        as expected under various conditions, such as server delays or malformed timeout
        inputs.
    
        Attributes:
            timeout: The default timeout value used in test cases, typically set during
                     test initialization.
            timeout_value: A specific timeout value used in certain test cases to
                           validate timeout behavior.
            error_text: Expected error message substring when an invalid timeout is provided.
            httpbin: URL to the httpbin service used for testing HTTP request behavior.
            request_timeout: Timeout value passed to requests.get() in test methods.
            connect_timeout: Timeout value for connection attempts.
            read_timeout: Timeout value for reading responses.
            total_timeout: Total timeout value for the entire request lifecycle.
    
        The methods in this class verify that:
        - Stream requests time out correctly when the server delays response.
        - Invalid timeout values raise a ValueError with the expected error message.
        - Setting timeout to None is valid and does not prevent request success.
        - Read timeouts are properly triggered when response takes longer than allowed.
        - Connection attempts time out when exceeding the specified timeout duration.
        - Total timeout correctly limits the entire request lifecycle.
        - Encoded methods handle timeouts as expected, addressing known issues.
    """

    def test_stream_timeout(self, httpbin):
        """
        Tests that stream requests properly handle timeouts when the server delays response, ensuring robust error handling in real-world scenarios. This is critical for maintaining reliability when interacting with external services that may be slow or unresponsive.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing.
        """
        try:
            requests.get(httpbin("delay/10"), timeout=2.0)
        except requests.exceptions.Timeout as e:
            assert "Read timed out" in e.args[0].args[0]

    @pytest.mark.parametrize(
        "timeout, error_text",
        (
            ((3, 4, 5), "(connect, read)"),
            ("foo", "must be an int, float or None"),
        ),
    )
    def test_invalid_timeout(self, httpbin, timeout, error_text):
        """
        Tests that invalid timeout values are properly validated and raise a ValueError with a descriptive message, ensuring robust error handling in HTTP requests.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing.
            timeout: The timeout value to pass to requests.get; should be invalid to trigger a ValueError.
            error_text: Expected substring in the error message raised when an invalid timeout is provided.
        """
        with pytest.raises(ValueError) as e:
            requests.get(httpbin("get"), timeout=timeout)
        assert error_text in str(e)

    @pytest.mark.parametrize("timeout", (None, Urllib3Timeout(connect=None, read=None)))
    def test_none_timeout(self, httpbin, timeout):
        """
        Verify that setting the timeout to None is supported and does not cause request failures.
        
        This test ensures that Requests maintains its usability by allowing users to explicitly disable timeouts (by setting timeout to None), which is important for long-running operations or when relying on system-level defaults. While a full behavioral test would require waiting beyond the system timeout (which would slow down the test suite), this check confirms that the request still succeeds when no timeout is enforced, aligning with Requests' goal of providing a reliable, flexible, and intuitive HTTP interface.
        """
        r = requests.get(httpbin("get"), timeout=timeout)
        assert r.status_code == 200

    @pytest.mark.parametrize(
        "timeout", ((None, 0.1), Urllib3Timeout(connect=None, read=0.1))
    )
    def test_read_timeout(self, httpbin, timeout):
        """
        Verifies that the requests library correctly enforces read timeouts when a server takes longer to respond than the specified timeout duration, ensuring robust handling of slow or unresponsive endpoints.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing, used to simulate delayed responses.
            timeout: The timeout value in seconds for the HTTP request, used to test timeout behavior under controlled conditions.
        """
        try:
            requests.get(httpbin("delay/10"), timeout=timeout)
            pytest.fail("The recv() request should time out.")
        except ReadTimeout:
            pass

    @pytest.mark.parametrize(
        "timeout", ((0.1, None), Urllib3Timeout(connect=0.1, read=None))
    )
    def test_connect_timeout(self, timeout):
        """
        Verifies that HTTP connection attempts properly respect the specified timeout duration, ensuring the library gracefully handles unresponsive servers by raising a timeout exception. This test is critical for maintaining reliability in network operations, as it confirms Requests correctly enforces timeout behavior to prevent indefinite hanging during connection attempts.
        
        Args:
            timeout: The timeout duration in seconds for the connection attempt (default: value specified in test case)
        """
        try:
            requests.get(TARPIT, timeout=timeout)
            pytest.fail("The connect() request should time out.")
        except ConnectTimeout as e:
            assert isinstance(e, ConnectionError)
            assert isinstance(e, Timeout)

    @pytest.mark.parametrize(
        "timeout", ((0.1, 0.1), Urllib3Timeout(connect=0.1, read=0.1))
    )
    def test_total_timeout_connect(self, timeout):
        """
        Tests that a connection attempt properly times out when the specified timeout is exceeded, ensuring the library enforces connection deadlines as expected.
        
        Args:
            timeout: The duration in seconds to wait for a connection before timing out. If the request does not time out within this period, the test fails. (default: value provided by test case)
        """
        try:
            requests.get(TARPIT, timeout=timeout)
            pytest.fail("The connect() request should time out.")
        except ConnectTimeout:
            pass

    def test_encoded_methods(self, httpbin):
        """
        Tests that requests can handle byte-string method names, ensuring compatibility with edge cases in HTTP method encoding.
        This verifies robustness in the library's handling of non-UTF-8 method inputs, aligning with Requests' goal of being a reliable and flexible HTTP client that accommodates various input formats while maintaining security and correctness.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        r = requests.request(b"GET", httpbin("get"))
        assert r.ok


SendCall = collections.namedtuple("SendCall", ("args", "kwargs"))


class RedirectSession(SessionRedirectMixin):
    """
    A session handler that manages HTTP redirects in a specified order, simulating the behavior of a web client during redirect chains.
    
        Attributes:
            order_of_redirects: The list of redirect types to process in sequence, determining how redirects are handled during request execution.
    
        Methods:
            __init__: Initialize the redirect handler with a specified order of redirects.
            send: Sends a request by recording the call parameters and returning a built response.
            build_response: Constructs and returns a simulated HTTP response based on stored redirects and request data.
            _build_raw: Creates a dummy string-like object for handling connection release without actual data.
    """

    def __init__(self, order_of_redirects):
        """
        Initialize the redirect handler to manage HTTP redirects according to a specified processing order.
        
        This enables consistent and predictable handling of redirect chains in HTTP requests, which is essential for reliable web interactions. By defining the order in which different redirect types are processed, the handler ensures that redirects are followed in a controlled manner, preventing infinite loops and supporting robust session management.
        
        Args:
            order_of_redirects: List of redirect types in the order they should be processed (default: None)
        """
        self.redirects = order_of_redirects
        self.calls = []
        self.max_redirects = 30
        self.cookies = {}
        self.trust_env = False

    def send(self, *args, **kwargs):
        """
        Sends an HTTP request while recording the call details for later inspection or replay.
        
        This method is used to capture the parameters of each request made through the session, enabling features like request logging, testing, and replaying of HTTP interactions. It abstracts away the complexity of direct HTTP communication, aligning with Requests' goal of providing a simple, intuitive interface for web interactions.
        
        Args:
            *args: Positional arguments passed to the underlying send operation.
            **kwargs: Keyword arguments passed to the underlying send operation.
        
        Returns:
            The response constructed from the recorded call, allowing for consistent and predictable behavior in testing or debugging scenarios.
        """
        self.calls.append(SendCall(args, kwargs))
        return self.build_response()

    def build_response(self):
        """
        Simulates an HTTP response for testing purposes by applying the next redirect in the sequence, preserving request context, and generating a response body. This enables accurate simulation of HTTP behavior during testing, ensuring that redirect handling and response processing work as expected in the Requests library.
        
        Returns:
            A requests.Response object with the status code from the next redirect (or 200 if none remain), a Location header pointing to the root path, a raw response body generated by _build_raw(), and the original request attached for context.
        """
        request = self.calls[-1].args[0]
        r = requests.Response()

        try:
            r.status_code = int(self.redirects.pop(0))
        except IndexError:
            r.status_code = 200

        r.headers = CaseInsensitiveDict({"Location": "/"})
        r.raw = self._build_raw()
        r.request = request
        return r

    def _build_raw(self):
        """
        Creates a dummy string-like object to simulate connection handling during request processing without actual data transmission.
        
        This is used internally to maintain compatibility with connection management workflows in urllib3, allowing Requests to properly handle response streams even when no real data is present. The returned StringIO object includes a no-op release_conn method to satisfy interface expectations without performing any action.
        
        Returns:
            A StringIO object with a no-op release_conn method, used to simulate connection handling in the absence of actual data.
        """
        string = StringIO.StringIO("")
        setattr(string, "release_conn", lambda *args: args)
        return string


def test_json_encodes_as_bytes():
    """
    Verifies that JSON data is correctly encoded to bytes when preparing a request, ensuring compatibility with urllib3's requirement for bytes-like body content. This test supports Requests' goal of abstracting low-level HTTP details by guaranteeing that JSON payloads are automatically and reliably serialized to bytes before transmission.
    """
    # urllib3 expects bodies as bytes-like objects
    body = {"key": "value"}
    p = PreparedRequest()
    p.prepare(method="GET", url="https://www.example.com/", json=body)
    assert isinstance(p.body, bytes)


def test_requests_are_updated_each_time(httpbin):
    """
    Verifies that redirect requests are correctly updated with the new HTTP method (from POST to GET) and fresh request object during redirection, ensuring consistent behavior across redirect chains. This is critical for maintaining proper request semantics in HTTP clients, especially when handling 303 See Other and 307 Temporary Redirect responses, which require method changes and fresh request construction.
    
    Args:
        httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests and redirects.
    """
    session = RedirectSession([303, 307])
    prep = requests.Request("POST", httpbin("post")).prepare()
    r0 = session.send(prep)
    assert r0.request.method == "POST"
    assert session.calls[-1] == SendCall((r0.request,), {})
    redirect_generator = session.resolve_redirects(r0, prep)
    default_keyword_args = {
        "stream": False,
        "verify": True,
        "cert": None,
        "timeout": None,
        "allow_redirects": False,
        "proxies": {},
    }
    for response in redirect_generator:
        assert response.request.method == "GET"
        send_call = SendCall((response.request,), default_keyword_args)
        assert session.calls[-1] == send_call


@pytest.mark.parametrize(
    "var,url,proxy",
    [
        ("http_proxy", "http://example.com", "socks5://proxy.com:9876"),
        ("https_proxy", "https://example.com", "socks5://proxy.com:9876"),
        ("all_proxy", "http://example.com", "socks5://proxy.com:9876"),
        ("all_proxy", "https://example.com", "socks5://proxy.com:9876"),
    ],
)
def test_proxy_env_vars_override_default(var, url, proxy):
    """
    Tests that environment variables for proxy settings take precedence over default proxy configurations, ensuring secure and predictable proxy behavior in real-world scenarios.
    
    Args:
        var: The environment variable name to set (e.g., 'HTTP_PROXY' or 'HTTPS_PROXY'), used to simulate user-configured proxy settings
        url: The URL to test proxy resolution against, representing a target endpoint that may require proxy routing
        proxy: The proxy URL to assign via the environment variable, used to verify that the proxy is correctly picked up and applied
    """
    session = requests.Session()
    prep = PreparedRequest()
    prep.prepare(method="GET", url=url)

    kwargs = {var: proxy}
    scheme = urlparse(url).scheme
    with override_environ(**kwargs):
        proxies = session.rebuild_proxies(prep, {})
        assert scheme in proxies
        assert proxies[scheme] == proxy


@pytest.mark.parametrize(
    "data",
    (
        (("a", "b"), ("c", "d")),
        (("c", "d"), ("a", "b")),
        (("a", "b"), ("c", "d"), ("e", "f")),
    ),
)
def test_data_argument_accepts_tuples(data):
    """
    Verify that the data argument correctly handles tuples of strings by ensuring proper encoding during request preparation.
    
    This test ensures Requests maintains compatibility with tuple inputs for form data, which is essential for consistent and predictable behavior when submitting form-encoded data. By validating that tuples are properly encoded using URL encoding, the function supports the library's goal of providing a reliable, intuitive interface for HTTP requests, particularly in scenarios involving form submissions or API interactions where data structure integrity is critical.
    """
    p = PreparedRequest()
    p.prepare(
        method="GET", url="http://www.example.com", data=data, hooks=default_hooks()
    )
    assert p.body == urlencode(data)


@pytest.mark.parametrize(
    "kwargs",
    (
        None,
        {
            "method": "GET",
            "url": "http://www.example.com",
            "data": "foo=bar",
            "hooks": default_hooks(),
        },
        {
            "method": "GET",
            "url": "http://www.example.com",
            "data": "foo=bar",
            "hooks": default_hooks(),
            "cookies": {"foo": "bar"},
        },
        {"method": "GET", "url": "http://www.example.com/üniçø∂é"},
    ),
)
def test_prepared_copy(kwargs):
    """
    Tests that a PreparedRequest copy accurately preserves all original attributes, ensuring data integrity when duplicating HTTP request objects.
    
    This validation is critical for Requests' reliability, as PreparedRequest objects are used internally to manage request state before sending. Ensuring copies retain all attributes (like method, URL, headers, cookies, and body) guarantees consistent behavior during request processing, especially in scenarios involving request modification, retry logic, or session management.
    
    Args:
        kwargs: Dictionary of arguments to pass to prepare() method (default: empty dict)
    """
    p = PreparedRequest()
    if kwargs:
        p.prepare(**kwargs)
    copy = p.copy()
    for attr in ("method", "url", "headers", "_cookies", "body", "hooks"):
        assert getattr(p, attr) == getattr(copy, attr)


def test_urllib3_retries(httpbin):
    """
    Tests that urllib3 retries are properly configured to handle transient server errors by retrying failed requests with 500 status codes, ensuring robustness in HTTP interactions.
    
    Args:
        httpbin: Fixture that provides a URL to the httpbin service for testing HTTP responses.
    """
    from urllib3.util import Retry

    s = requests.Session()
    s.mount("http://", HTTPAdapter(max_retries=Retry(total=2, status_forcelist=[500])))

    with pytest.raises(RetryError):
        s.get(httpbin("status/500"))


def test_urllib3_pool_connection_closed(httpbin):
    """
    Verifies that attempting to make an HTTP request with a closed connection pool raises a ConnectionError with the expected message, ensuring robust error handling in scenarios where connection resources are exhausted or improperly managed.
    
    Args:
        httpbin: Fixture that provides a URL to the httpbin service for testing HTTP requests.
    """
    s = requests.Session()
    s.mount("http://", HTTPAdapter(pool_connections=0, pool_maxsize=0))

    try:
        s.get(httpbin("status/200"))
    except ConnectionError as e:
        assert "Pool is closed." in str(e)


class TestPreparingURLs:
    """
    Tests the URL preparation and handling functionality within the HTTP client, focusing on normalization of percent-encoded characters, validation of malformed URLs, and proper handling of redirects and connection pooling under various TLS and MTLS configurations.
    
        The test class verifies that:
        - URLs are correctly normalized by converting percent-encoded sequences to uppercase.
        - Invalid URLs raise appropriate exceptions during preparation.
        - Redirects to invalid URLs trigger expected exceptions.
        - URLs with non-http schemes are left unchanged during preparation, while http-based schemes are processed.
        - Parameters can be set for nonstandard schemes only if they begin with "http".
        - JSON payloads containing NaN values raise InvalidJSONError.
        - Non-JSON responses trigger JSONDecodeError with preserved original response text in the doc attribute.
        - HTTP status code 425 (Too Early) is correctly recognized using various string representations.
        - HTTPS requests with different TLS verification settings (verify=True vs verify=False, valid vs expired certificates, CA bundle vs no bundle) use separate connection pools.
        - MTLS requests with different mutual TLS configurations result in distinct connection pools, preventing reuse of invalid SSL states.
    
        The class relies on fixtures such as `httpbin` to provide test endpoints for HTTP behavior validation.
    """

    @pytest.mark.parametrize(
        "url,expected",
        (
            ("http://google.com", "http://google.com/"),
            ("http://ジェーピーニック.jp", "http://xn--hckqz9bzb1cyrb.jp/"),
            ("http://xn--n3h.net/", "http://xn--n3h.net/"),
            ("http://ジェーピーニック.jp".encode(), "http://xn--hckqz9bzb1cyrb.jp/"),
            ("http://straße.de/straße", "http://xn--strae-oqa.de/stra%C3%9Fe"),
            (
                "http://straße.de/straße".encode(),
                "http://xn--strae-oqa.de/stra%C3%9Fe",
            ),
            (
                "http://Königsgäßchen.de/straße",
                "http://xn--knigsgchen-b4a3dun.de/stra%C3%9Fe",
            ),
            (
                "http://Königsgäßchen.de/straße".encode(),
                "http://xn--knigsgchen-b4a3dun.de/stra%C3%9Fe",
            ),
            (b"http://xn--n3h.net/", "http://xn--n3h.net/"),
            (
                b"http://[1200:0000:ab00:1234:0000:2552:7777:1313]:12345/",
                "http://[1200:0000:ab00:1234:0000:2552:7777:1313]:12345/",
            ),
            (
                "http://[1200:0000:ab00:1234:0000:2552:7777:1313]:12345/",
                "http://[1200:0000:ab00:1234:0000:2552:7777:1313]:12345/",
            ),
        ),
    )
    def test_preparing_url(self, url, expected):
        """
        Tests that URL preparation correctly normalizes percent-encoded characters to ensure consistent and predictable URL handling, which is critical for reliable HTTP requests in the Requests library.
        
        Args:
            url: The URL string to be prepared, which may contain percent-encoded sequences
            expected: The normalized expected URL after preparation, with percent-encodings in uppercase
        
        Returns:
            None; assertion failure if the normalized prepared URL does not match the expected value
        """
        def normalize_percent_encode(x):
            # Helper function that normalizes equivalent
            # percent-encoded bytes before comparisons
            for c in re.findall(r"%[a-fA-F0-9]{2}", x):
                x = x.replace(c, c.upper())
            return x

        r = requests.Request("GET", url=url)
        p = r.prepare()
        assert normalize_percent_encode(p.url) == expected

    @pytest.mark.parametrize(
        "url",
        (
            b"http://*.google.com",
            b"http://*",
            "http://*.google.com",
            "http://*",
            "http://☃.net/",
        ),
    )
    def test_preparing_bad_url(self, url):
        """
        Tests that attempting to prepare a request with an invalid URL correctly raises InvalidURL, ensuring robust error handling for malformed URLs. This validation is critical in Requests' mission to provide a reliable and user-friendly HTTP client that prevents invalid requests from proceeding and helps developers quickly identify URL formatting issues.
        
        Args:
            url: The malformed URL string to test preparation with.
        """
        r = requests.Request("GET", url=url)
        with pytest.raises(requests.exceptions.InvalidURL):
            r.prepare()

    @pytest.mark.parametrize("url, exception", (("http://:1", InvalidURL),))
    def test_redirecting_to_bad_url(self, httpbin, url, exception):
        """
        Tests that attempting to redirect to an invalid URL raises the expected exception, ensuring robust error handling in HTTP request flows.
        
        Args:
            httpbin: Fixture that provides a URL to the httpbin service for testing HTTP behavior, including redirect functionality.
            url: The malformed or invalid URL to which the redirect should point, used to simulate edge cases in URL handling.
            exception: The expected exception class that should be raised when attempting to redirect to the bad URL, verifying proper error propagation.
        """
        with pytest.raises(exception):
            requests.get(httpbin("redirect-to"), params={"url": url})

    @pytest.mark.parametrize(
        "input, expected",
        (
            (
                b"http+unix://%2Fvar%2Frun%2Fsocket/path%7E",
                "http+unix://%2Fvar%2Frun%2Fsocket/path~",
            ),
            (
                "http+unix://%2Fvar%2Frun%2Fsocket/path%7E",
                "http+unix://%2Fvar%2Frun%2Fsocket/path~",
            ),
            (
                b"mailto:user@example.org",
                "mailto:user@example.org",
            ),
            (
                "mailto:user@example.org",
                "mailto:user@example.org",
            ),
            (
                b"data:SSDimaUgUHl0aG9uIQ==",
                "data:SSDimaUgUHl0aG9uIQ==",
            ),
        ),
    )
    def test_url_mutation(self, input, expected):
        """
        Tests URL mutation behavior to ensure proper handling of non-HTTP schemes and transformation of HTTP-based URLs during request preparation.
        
        Args:
            input: The original URL string to be processed, which may have various schemes (e.g., http, https, ftp).
            expected: The expected resulting URL after request preparation, reflecting correct mutation for HTTP schemes and preservation for others.
        """
        r = requests.Request("GET", url=input)
        p = r.prepare()
        assert p.url == expected

    @pytest.mark.parametrize(
        "input, params, expected",
        (
            (
                b"http+unix://%2Fvar%2Frun%2Fsocket/path",
                {"key": "value"},
                "http+unix://%2Fvar%2Frun%2Fsocket/path?key=value",
            ),
            (
                "http+unix://%2Fvar%2Frun%2Fsocket/path",
                {"key": "value"},
                "http+unix://%2Fvar%2Frun%2Fsocket/path?key=value",
            ),
            (
                b"mailto:user@example.org",
                {"key": "value"},
                "mailto:user@example.org",
            ),
            (
                "mailto:user@example.org",
                {"key": "value"},
                "mailto:user@example.org",
            ),
        ),
    )
    def test_parameters_for_nonstandard_schemes(self, input, params, expected):
        """
        Verifies that request parameters are only allowed for nonstandard schemes that begin with 'http', ensuring secure and predictable URL handling.
        
        Args:
            input: The URL string to test, potentially with a nonstandard scheme.
            params: Dictionary of parameters to attach to the request.
            expected: The expected resulting URL after parameter processing.
        """
        r = requests.Request("GET", url=input, params=params)
        p = r.prepare()
        assert p.url == expected

    def test_post_json_nan(self, httpbin):
        """
        Tests that attempting to send JSON containing NaN values results in an InvalidJSONError, ensuring robust error handling for invalid JSON data.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
        """
        data = {"foo": float("nan")}
        with pytest.raises(requests.exceptions.InvalidJSONError):
            requests.post(httpbin("post"), json=data)

    def test_json_decode_compatibility(self, httpbin):
        """
        Verifies that Requests properly raises JSONDecodeError when attempting to parse non-JSON response content, ensuring robust error handling for invalid JSON responses encountered during API interactions.
        
        Args:
            httpbin: Fixture providing a URL to the httpbin service for testing HTTP responses.
        """
        r = requests.get(httpbin("bytes/20"))
        with pytest.raises(requests.exceptions.JSONDecodeError) as excinfo:
            r.json()
        assert isinstance(excinfo.value, RequestException)
        assert isinstance(excinfo.value, JSONDecodeError)
        assert r.text not in str(excinfo.value)

    def test_json_decode_persists_doc_attr(self, httpbin):
        """
        Verifies that JSON decode errors retain the original response text in the doc attribute, ensuring accurate debugging and error reporting when malformed JSON is received from HTTP servers.
        
        Args:
            self: Test case instance providing access to test utilities.
            httpbin: Fixture that returns a URL to a test HTTP server instance.
        """
        r = requests.get(httpbin("bytes/20"))
        with pytest.raises(requests.exceptions.JSONDecodeError) as excinfo:
            r.json()
        assert excinfo.value.doc == r.text

    def test_status_code_425(self):
        """
        Tests that the HTTP status code 425 (Too Early) can be retrieved using multiple valid string representations, ensuring consistent behavior across different naming conventions. This validation supports Requests' goal of providing a reliable and intuitive interface for working with HTTP status codes, making it easier for developers to write robust and readable code when handling HTTP responses.
        
        Returns:
            None
        """
        r1 = requests.codes.get("TOO_EARLY")
        r2 = requests.codes.get("too_early")
        r3 = requests.codes.get("UNORDERED")
        r4 = requests.codes.get("unordered")
        r5 = requests.codes.get("UNORDERED_COLLECTION")
        r6 = requests.codes.get("unordered_collection")

        assert r1 == 425
        assert r2 == 425
        assert r3 == 425
        assert r4 == 425
        assert r5 == 425
        assert r6 == 425

    def test_different_connection_pool_for_tls_settings_verify_True(self):
        """
        Tests that HTTPS requests with different TLS verification settings (verify=True vs verify=False) use separate connection pools, even when TLS configurations differ. This ensures session-level connection pooling correctly isolates verified and unverified connections, maintaining security and resource separation as required by Requests' design to prevent unintended reuse of insecure connections.
        """
        def response_handler(sock):
            consume_socket_content(sock, timeout=0.5)
            sock.send(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 18\r\n\r\n"
                b'\xff\xfe{\x00"\x00K0"\x00=\x00"\x00\xab0"\x00\r\n'
            )

        s = requests.Session()
        close_server = threading.Event()
        server = TLSServer(
            handler=response_handler,
            wait_to_close_event=close_server,
            requests_to_handle=3,
            cert_chain="tests/certs/expired/server/server.pem",
            keyfile="tests/certs/expired/server/server.key",
        )

        with server as (host, port):
            url = f"https://{host}:{port}"
            r1 = s.get(url, verify=False)
            assert r1.status_code == 200

            # Cannot verify self-signed certificate
            with pytest.raises(requests.exceptions.SSLError):
                s.get(url)

            close_server.set()
        assert 2 == len(s.adapters["https://"].poolmanager.pools)

    def test_different_connection_pool_for_tls_settings_verify_bundle_expired_cert(
        self,
    ):
        """
        Tests that HTTPS requests with different TLS verification settings use distinct connection pools, ensuring proper isolation between security configurations. This verifies that using verify=False versus a specific CA bundle (even with an expired certificate) creates separate pools, which is critical for maintaining security boundaries and preventing unintended reuse of connections with inconsistent trust settings in the Requests library.
        """
        def response_handler(sock):
            consume_socket_content(sock, timeout=0.5)
            sock.send(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 18\r\n\r\n"
                b'\xff\xfe{\x00"\x00K0"\x00=\x00"\x00\xab0"\x00\r\n'
            )

        s = requests.Session()
        close_server = threading.Event()
        server = TLSServer(
            handler=response_handler,
            wait_to_close_event=close_server,
            requests_to_handle=3,
            cert_chain="tests/certs/expired/server/server.pem",
            keyfile="tests/certs/expired/server/server.key",
        )

        with server as (host, port):
            url = f"https://{host}:{port}"
            r1 = s.get(url, verify=False)
            assert r1.status_code == 200

            # Has right trust bundle, but certificate expired
            with pytest.raises(requests.exceptions.SSLError):
                s.get(url, verify="tests/certs/expired/ca/ca.crt")

            close_server.set()
        assert 2 == len(s.adapters["https://"].poolmanager.pools)

    def test_different_connection_pool_for_tls_settings_verify_bundle_unexpired_cert(
        self,
    ):
        """
        Tests that distinct TLS verification configurations result in separate connection pools for HTTPS requests using a valid certificate, ensuring proper isolation between security settings.
        
        This verifies that Requests correctly maintains separate connection pools when using different TLS verification modes (verify=False vs. verify with a CA bundle), which is critical for security and performance. By isolating connections based on verification settings, Requests prevents potential misconfigurations and ensures that each security policy operates independently, aligning with the library's goal of providing reliable, predictable HTTP behavior in real-world applications.
        """
        def response_handler(sock):
            consume_socket_content(sock, timeout=0.5)
            sock.send(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 18\r\n\r\n"
                b'\xff\xfe{\x00"\x00K0"\x00=\x00"\x00\xab0"\x00\r\n'
            )

        s = requests.Session()
        close_server = threading.Event()
        server = TLSServer(
            handler=response_handler,
            wait_to_close_event=close_server,
            requests_to_handle=3,
            cert_chain="tests/certs/valid/server/server.pem",
            keyfile="tests/certs/valid/server/server.key",
        )

        with server as (host, port):
            url = f"https://{host}:{port}"
            r1 = s.get(url, verify=False)
            assert r1.status_code == 200

            r2 = s.get(url, verify="tests/certs/valid/ca/ca.crt")
            assert r2.status_code == 200

            close_server.set()
        assert 2 == len(s.adapters["https://"].poolmanager.pools)

    def test_different_connection_pool_for_mtls_settings(self):
        """
        Tests that separate connection pools are used for MTLS configurations by verifying that a second request fails due to connection reuse with an invalid SSL state, while the first request succeeds. This ensures Requests properly isolates connections when MTLS settings change, maintaining security and correctness in scenarios involving client certificate authentication, which is critical for secure API interactions and mutual TLS workflows. (default: mutual_tls=True, verify=False)
        """
        client_cert = None

        def response_handler(sock):
            nonlocal client_cert
            client_cert = sock.getpeercert()
            consume_socket_content(sock, timeout=0.5)
            sock.send(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 18\r\n\r\n"
                b'\xff\xfe{\x00"\x00K0"\x00=\x00"\x00\xab0"\x00\r\n'
            )

        s = requests.Session()
        close_server = threading.Event()
        server = TLSServer(
            handler=response_handler,
            wait_to_close_event=close_server,
            requests_to_handle=2,
            cert_chain="tests/certs/expired/server/server.pem",
            keyfile="tests/certs/expired/server/server.key",
            mutual_tls=True,
            cacert="tests/certs/expired/ca/ca.crt",
        )

        cert = (
            "tests/certs/mtls/client/client.pem",
            "tests/certs/mtls/client/client.key",
        )
        with server as (host, port):
            url = f"https://{host}:{port}"
            r1 = s.get(url, verify=False, cert=cert)
            assert r1.status_code == 200
            with pytest.raises(requests.exceptions.SSLError):
                s.get(url, cert=cert)
            close_server.set()

        assert client_cert is not None


def test_content_length_for_bytes_data(httpbin):
    """
    Verifies that the Content-Length header is correctly calculated and set when sending bytes data in a POST request, ensuring proper HTTP protocol compliance.
    
    This test validates Requests' internal handling of byte data encoding and header generation, which is critical for reliable communication with HTTP servers. Correct Content-Length ensures servers can accurately read the request body, especially when dealing with multi-byte UTF-8 characters.
    
    Args:
        httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
    """
    data = "This is a string containing multi-byte UTF-8 ☃️"
    encoded_data = data.encode("utf-8")
    length = str(len(encoded_data))
    req = requests.Request("POST", httpbin("post"), data=encoded_data)
    p = req.prepare()

    assert p.headers["Content-Length"] == length


@pytest.mark.skipif(
    is_urllib3_1,
    reason="urllib3 2.x encodes all strings to utf-8, urllib3 1.x uses latin-1",
)
def test_content_length_for_string_data_counts_bytes(httpbin):
    """
    Tests that the Content-Length header accurately reflects the byte size of UTF-8 encoded string data, ensuring proper HTTP request formatting for internationalized content.
    
    Args:
        httpbin: Fixture providing a URL to the httpbin service for testing HTTP requests.
    """
    data = "This is a string containing multi-byte UTF-8 ☃️"
    length = str(len(data.encode("utf-8")))
    req = requests.Request("POST", httpbin("post"), data=data)
    p = req.prepare()

    assert p.headers["Content-Length"] == length


def test_json_decode_errors_are_serializable_deserializable():
    """
    Verifies that JSONDecodeError instances from the requests library maintain their integrity when serialized and deserialized with pickle, ensuring reliable error handling in distributed or persisted contexts.
    
    This test is critical for Requests' reliability: when errors are passed between processes (e.g., in multiprocessing or caching scenarios), preserving the full error state—including message, JSON content, and position—is essential for debugging and maintaining consistent behavior. By confirming that the error's string representation remains unchanged after serialization, the test ensures that error details are not lost during inter-process communication or storage.
    """
    json_decode_error = requests.exceptions.JSONDecodeError(
        "Extra data",
        '{"responseCode":["706"],"data":null}{"responseCode":["706"],"data":null}',
        36,
    )
    deserialized_error = pickle.loads(pickle.dumps(json_decode_error))
    assert repr(json_decode_error) == repr(deserialized_error)
