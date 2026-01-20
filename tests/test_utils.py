import copy
import filecmp
import os
import tarfile
import zipfile
from collections import deque
from io import BytesIO
from unittest import mock

import pytest

from requests import compat
from requests._internal_utils import unicode_is_ascii
from requests.cookies import RequestsCookieJar
from requests.structures import CaseInsensitiveDict
from requests.utils import (
    _parse_content_type_header,
    add_dict_to_cookiejar,
    address_in_network,
    dotted_netmask,
    extract_zipped_paths,
    get_auth_from_url,
    get_encoding_from_headers,
    get_encodings_from_content,
    get_environ_proxies,
    get_netrc_auth,
    guess_filename,
    guess_json_utf,
    is_ipv4_address,
    is_valid_cidr,
    iter_slices,
    parse_dict_header,
    parse_header_links,
    prepend_scheme_if_needed,
    requote_uri,
    select_proxy,
    set_environ,
    should_bypass_proxies,
    super_len,
    to_key_val_list,
    to_native_string,
    unquote_header_value,
    unquote_unreserved,
    urldefragauth,
)

from .compat import StringIO, cStringIO


class TestSuperLen:
    """
    A test class for verifying the behavior of the super_len function across various input types and edge cases.
    
        Methods:
        - test_io_streams: Ensures that we properly deal with different kinds of IO streams.
        - test_super_len_correctly_calculates_len_of_partially_read_file: Ensure that we handle partially consumed file like objects.
        - test_super_len_handles_files_raising_weird_errors_in_tell: If tell() raises errors, assume the cursor is at position zero.
        - test_super_len_tell_ioerror: Ensure that if tell gives an IOError super_len doesn't fail
        - test_string: Tests that the super_len function correctly returns the length of a string.
        - test_file: Test file operations and warning counting for different file modes.
        - test_tarfile_member: Tests that a file extracted from a tar archive has the correct length.
        - test_super_len_with__len__: Tests that super_len correctly returns the length of a list by calling the built-in len function.
        - test_super_len_with_no__len__: Tests that super_len correctly retrieves the len attribute from an object without a __len__ method.
        - test_super_len_with_tell: Tests the behavior of super_len with a StringIO object, verifying that it correctly reports the remaining length after reading.
        - test_super_len_with_fileno: Tests that super_len correctly returns the length of a file object's content when accessed via fileno.
        - test_super_len_with_no_matches: Ensure that objects without any length methods default to 0
    """

    @pytest.mark.parametrize(
        "stream, value",
        (
            (StringIO.StringIO, "Test"),
            (BytesIO, b"Test"),
            pytest.param(
                cStringIO, "Test", marks=pytest.mark.skipif("cStringIO is None")
            ),
        ),
    )
    def test_io_streams(self, stream, value):
        """
        Verifies correct handling of various IO stream types to ensure robustness in request data processing.
        
        Args:
            stream: A callable that returns an IO stream instance, used to test different stream implementations.
            value: The input data to be written to the stream, used to validate stream length after writing.
        """
        assert super_len(stream()) == 0
        assert super_len(stream(value)) == 4

    def test_super_len_correctly_calculates_len_of_partially_read_file(self):
        """
        Verify that super_len correctly calculates the length of a file-like object that has been partially read, ensuring accurate length detection even when data has been consumed from the stream.
        
        This test is critical for maintaining reliable behavior in Requests when processing response bodies, particularly in scenarios involving streaming or partial reads, where accurate length tracking is essential for proper handling of content and resource management.
        """
        s = StringIO.StringIO()
        s.write("foobarbogus")
        assert super_len(s) == 0

    @pytest.mark.parametrize("error", [IOError, OSError])
    def test_super_len_handles_files_raising_weird_errors_in_tell(self, error):
        """
        Ensures super_len correctly handles files that raise unexpected errors from the tell() method by defaulting to position zero.
        
        This behavior is crucial for robustness in Requests, where file-like objects may exhibit unpredictable behavior during HTTP streaming or request body handling. By assuming the cursor is at position zero when tell() fails, super_len maintains reliability and prevents crashes in edge cases.
        
        Args:
            error: Exception class to raise in the tell() method, simulating various error conditions
        
        Returns:
            0, as super_len defaults to zero when tell() raises an error, ensuring safe fallback behavior
        """

        class BoomFile:
            def __len__(self):
                return 5

            def tell(self):
                raise error()

        assert super_len(BoomFile()) == 0

    @pytest.mark.parametrize("error", [IOError, OSError])
    def test_super_len_tell_ioerror(self, error):
        """
        Ensure that super_len gracefully handles IOError from tell() to maintain robustness in file-like objects.
        
        This test verifies that super_len does not fail when the underlying file-like object raises an IOError during a call to tell(), which is critical for handling unreliable or corrupted file streams. In the context of Requests, this ensures that streaming responses and file-like data handling remain resilient even when low-level I/O operations encounter unexpected errors, supporting the library's goal of providing reliable and user-friendly HTTP interactions.
        """

        class NoLenBoomFile:
            def tell(self):
                raise error()

            def seek(self, offset, whence):
                pass

        assert super_len(NoLenBoomFile()) == 0

    def test_string(self):
        """
        Tests that the super_len function correctly calculates the length of a string, ensuring it behaves as expected for basic string inputs.
        
        This test verifies the fundamental functionality of super_len, which is essential for any string manipulation operation in the Requests library. Accurate length calculation is critical for handling headers, query parameters, and other string-based components of HTTP requests, ensuring reliable and predictable behavior in real-world usage scenarios.
        """
        assert super_len("Test") == 4

    @pytest.mark.parametrize(
        "mode, warnings_num",
        (
            ("r", 1),
            ("rb", 0),
        ),
    )
    def test_file(self, tmpdir, mode, warnings_num, recwarn):
        """
        Test file operations and warning counting for different file modes to ensure proper behavior during file handling in the Requests library.
        
        Args:
            tmpdir: Temporary directory fixture used to create a test file, ensuring isolated and clean test environments.
            mode: File opening mode (e.g., 'r', 'w', 'rb') to test, simulating various real-world file access scenarios.
            warnings_num: Expected number of warnings to be captured during the test, verifying correct warning emission during file operations.
            recwarn: Warning recording fixture to verify warning count, ensuring the library handles file-related warnings appropriately.
        """
        file_obj = tmpdir.join("test.txt")
        file_obj.write("Test")
        with file_obj.open(mode) as fd:
            assert super_len(fd) == 4
        assert len(recwarn) == warnings_num

    def test_tarfile_member(self, tmpdir):
        """
        Verifies that extracted files from a tar archive maintain correct content length, ensuring data integrity during archive operations.
        
        Args:
            tmpdir: Temporary directory fixture used to create test files and archives.
        """
        file_obj = tmpdir.join("test.txt")
        file_obj.write("Test")

        tar_obj = str(tmpdir.join("test.tar"))
        with tarfile.open(tar_obj, "w") as tar:
            tar.add(str(file_obj), arcname="test.txt")

        with tarfile.open(tar_obj) as tar:
            member = tar.extractfile("test.txt")
            assert super_len(member) == 4

    def test_super_len_with__len__(self):
        """
        Tests that super_len correctly delegates to the built-in len function for lists, ensuring consistent behavior with Python's standard library.
        
        This test verifies the correctness of super_len's implementation in the context of Requests' focus on reliable and predictable data handling, ensuring that length calculations for container types like lists are accurate and consistent with expected Python behavior.
        """
        foo = [1, 2, 3, 4]
        len_foo = super_len(foo)
        assert len_foo == 4

    def test_super_len_with_no__len__(self):
        """
        Tests the fallback behavior of super_len when an object lacks a __len__ method, ensuring it can still retrieve length via a 'len' attribute.
        
        This validation supports Requests' goal of robust and flexible data handling by confirming that length detection works reliably even with non-standard objects, which is crucial when processing HTTP responses or custom data structures where consistent length access is needed.
        """
        class LenFile:
            def __init__(self):
                self.len = 5

        assert super_len(LenFile()) == 5

    def test_super_len_with_tell(self):
        """
        Tests that super_len accurately reflects the remaining readable length in a StringIO object after partial reads, ensuring correct behavior when tracking data availability during streaming or incremental processing. This is critical for Requests' internal handling of response bodies, where precise length tracking enables efficient memory usage and proper handling of chunked or streaming data.
        """
        foo = StringIO.StringIO("12345")
        assert super_len(foo) == 5
        foo.read(2)
        assert super_len(foo) == 3

    def test_super_len_with_fileno(self):
        """
        Tests that super_len accurately determines the size of a file's content when accessed through its file descriptor, ensuring reliable length detection for file operations within the Requests library's ecosystem. This verification supports robust file handling in scenarios involving streaming or low-level file I/O, which may be used in request body processing or file-based data transmission.
        """
        with open(__file__, "rb") as f:
            length = super_len(f)
            file_data = f.read()
        assert length == len(file_data)

    def test_super_len_with_no_matches(self):
        """
        Verify that super_len correctly handles objects lacking length methods by defaulting to 0, ensuring robustness in HTTP request handling where object length detection may be needed for data processing or streaming operations.
        
        This test ensures consistency in Requests' internal utilities, particularly when dealing with arbitrary objects during request body or header processing, where a reliable default length value prevents unexpected errors and maintains predictable behavior across diverse input types.
        """
        assert super_len(object()) == 0


class TestGetNetrcAuth:
    """
    Tests the functionality of the get_netrc_auth function in retrieving authentication credentials from a .netrc file.
    
        Methods:
        - test_works: Tests that get_netrc_auth correctly retrieves credentials from a .netrc file.
        - test_not_vulnerable_to_bad_url_parsing: Tests that the function is not vulnerable to malicious URL parsing by ensuring it returns None for a crafted URL with potential injection vectors.
    """

    def test_works(self, tmp_path, monkeypatch):
        """
        Tests that the get_netrc_auth function correctly extracts credentials from a .netrc file for HTTP authentication, ensuring secure and seamless access to protected resources in the Requests library.
        
        Args:
            tmp_path: Temporary directory path used to create a temporary .netrc file for testing.
            monkeypatch: pytest fixture to temporarily modify environment variables and file system to simulate real-world conditions.
        """
        netrc_path = tmp_path / ".netrc"
        monkeypatch.setenv("NETRC", str(netrc_path))
        with open(netrc_path, "w") as f:
            f.write("machine example.com login aaaa password bbbb\n")
        auth = get_netrc_auth("http://example.com/thing")
        assert auth == ("aaaa", "bbbb")

    def test_not_vulnerable_to_bad_url_parsing(self, tmp_path, monkeypatch):
        """
        Verifies that the URL parsing logic is resilient to malicious inputs by testing that a specially crafted URL containing potential injection vectors returns None, ensuring no unintended authentication credentials are extracted.
        
        Args:
            tmp_path: Temporary directory path used to create a temporary .netrc file (default: pytest's tmp_path fixture)
            monkeypatch: pytest fixture to temporarily modify environment variables and file system (default: pytest's monkeypatch fixture)
        """
        netrc_path = tmp_path / ".netrc"
        monkeypatch.setenv("NETRC", str(netrc_path))
        with open(netrc_path, "w") as f:
            f.write("machine example.com login aaaa password bbbb\n")
        auth = get_netrc_auth("http://example.com:@evil.com/&apos;")
        assert auth is None


class TestToKeyValList:
    """
    TestToKeyValList is a test class designed to validate the functionality of the to_key_val_list utility function.
    
        Methods:
        - test_valid: Tests that the input value converts correctly to a list of key-value pairs.
        - test_invalid: Tests that to_key_val_list raises ValueError when given a non-iterable input like a string.
    """

    @pytest.mark.parametrize(
        "value, expected",
        (
            ([("key", "val")], [("key", "val")]),
            ((("key", "val"),), [("key", "val")]),
            ({"key": "val"}, [("key", "val")]),
            (None, None),
        ),
    )
    def test_valid(self, value, expected):
        """
        Tests that valid input formats are correctly converted into key-value pairs, ensuring robust handling of data structures in HTTP request parameters.
        
        Args:
            value: The input to convert to a key-value list; must be compatible with to_key_val_list function
            expected: The expected result after conversion, used for assertion
        """
        assert to_key_val_list(value) == expected

    def test_invalid(self):
        """
        Tests input validation in to_key_val_list to ensure it properly rejects non-iterable inputs like strings.
        
        This validation is critical in Requests' data processing pipeline, where key-value pairs are frequently converted from various input types. By raising ValueError for non-iterable inputs, the function prevents downstream errors when processing request parameters, headers, or form data, maintaining data integrity and consistent behavior across the library's API.
        """
        with pytest.raises(ValueError):
            to_key_val_list("string")


class TestUnquoteHeaderValue:
    """
    TestUnquoteHeaderValue is a test class designed to validate the behavior of the unquote_header_value function in handling various header values, particularly focusing on proper unquoting of values with special characters and formatting.
    
        Attributes:
        - preserve_quotes: Controls whether quotes should be preserved in the output when unquoting header values.
        - expected: The expected result after unquoting a header value.
        - value: The header value to be unquoted and tested.
    
        The class methods test the correct unquoting of header values under different conditions, including handling of Windows-style paths and special characters. The attributes define the test parameters and expected outcomes, ensuring accurate validation of the unquoting logic.
    """

    @pytest.mark.parametrize(
        "value, expected",
        (
            (None, None),
            ("Test", "Test"),
            ('"Test"', "Test"),
            ('"Test\\\\"', "Test\\"),
            ('"\\\\Comp\\Res"', "\\Comp\\Res"),
        ),
    )
    def test_valid(self, value, expected):
        """
        Verifies that a header value, after unquoting, matches the expected plain text value.
        
        This ensures that HTTP header values, which may be enclosed in quotes (e.g., for values containing special characters), are correctly parsed and compared. This validation is critical for maintaining correct header handling in HTTP requests, aligning with the Requests library's goal of simplifying and standardizing HTTP interactions.
        
        Args:
            value: The header value to unquote and test.
            expected: The expected unquoted value for comparison.
        """
        assert unquote_header_value(value) == expected

    def test_is_filename(self):
        """
        Tests that unquote_header_value correctly preserves Windows-style paths with double backslashes when preserve_quotes is True, ensuring accurate handling of file paths in HTTP headers.
        
        This validation is critical for Requests' reliability when processing headers containing file paths on Windows systems, where backslashes are commonly used and must be preserved to maintain path integrity. Proper unquoting behavior ensures that file paths in headers (e.g., from Content-Disposition) are correctly interpreted without unintended escaping or transformation.
        """
        assert unquote_header_value('"\\\\Comp\\Res"', True) == "\\\\Comp\\Res"


class TestGetEnvironProxies:
    """
    Ensures that IP addresses are correctly matches with ranges
        in no_proxy variable.
    """


    @pytest.fixture(autouse=True, params=["no_proxy", "NO_PROXY"])
    def no_proxy(self, request, monkeypatch):
        """
        Sets the NO_PROXY environment variable to exclude specific hosts from proxy routing during HTTP tests.
        
        This ensures that requests to internal or local addresses (such as localhost or private subnets) bypass any configured proxy, which is essential for reliable test execution in environments where proxy settings might otherwise interfere with local service communication.
        
        Args:
            request: The pytest request object containing test parameters, used to determine the environment variable name via request.param.
            monkeypatch: The pytest monkeypatch fixture used to temporarily modify environment variables during the test.
        """
        monkeypatch.setenv(
            request.param, "192.168.0.0/24,127.0.0.1,localhost.localdomain,172.16.1.1"
        )

    @pytest.mark.parametrize(
        "url",
        (
            "http://192.168.0.1:5000/",
            "http://192.168.0.1/",
            "http://172.16.1.1/",
            "http://172.16.1.1:5000/",
            "http://localhost.localdomain:5000/v1.0/",
        ),
    )
    def test_bypass(self, url):
        """
        Tests that the system correctly returns no proxies when environment proxy settings are bypassed, ensuring direct connections to target URLs without proxy interference.
        
        Args:
            url: The URL to check for proxy settings, typically a target endpoint that should not use any proxy to maintain direct communication with the server.
        """
        assert get_environ_proxies(url, no_proxy=None) == {}

    @pytest.mark.parametrize(
        "url",
        (
            "http://192.168.1.1:5000/",
            "http://192.168.1.1/",
            "http://www.requests.com/",
        ),
    )
    def test_not_bypass(self, url):
        """
        Tests that proxy settings are properly applied when no_proxy is not configured, ensuring requests use configured proxies as expected.
        
        Args:
            url: The URL to evaluate proxy configuration for, verifying that proxies are not bypassed when no_proxy is not specified.
        """
        assert get_environ_proxies(url, no_proxy=None) != {}

    @pytest.mark.parametrize(
        "url",
        (
            "http://192.168.1.1:5000/",
            "http://192.168.1.1/",
            "http://www.requests.com/",
        ),
    )
    def test_bypass_no_proxy_keyword(self, url):
        """
        Tests that the no_proxy setting correctly bypasses proxy configuration for specified hosts, ensuring direct connections to trusted or local addresses without proxy interference.
        
        Args:
            url: The URL to test proxy configuration for, used to verify that hosts listed in no_proxy are not routed through a proxy
        """
        no_proxy = "192.168.1.1,requests.com"
        assert get_environ_proxies(url, no_proxy=no_proxy) == {}

    @pytest.mark.parametrize(
        "url",
        (
            "http://192.168.0.1:5000/",
            "http://192.168.0.1/",
            "http://172.16.1.1/",
            "http://172.16.1.1:5000/",
            "http://localhost.localdomain:5000/v1.0/",
        ),
    )
    def test_not_bypass_no_proxy_keyword(self, url, monkeypatch):
        """
        Tests that explicitly provided 'no_proxy' settings take precedence over the 'no_proxy' environment variable, ensuring predictable proxy bypass behavior in HTTP requests.
        
        Args:
            url: The URL to test proxy settings for, used to determine if proxy should be bypassed.
            monkeypatch: pytest fixture to temporarily modify environment variables for isolated testing.
        """
        # This is testing that the 'no_proxy' argument overrides the
        # environment variable 'no_proxy'
        monkeypatch.setenv("http_proxy", "http://proxy.example.com:3128/")
        no_proxy = "192.168.1.1,requests.com"
        assert get_environ_proxies(url, no_proxy=no_proxy) != {}


class TestIsIPv4Address:
    """
    Tests the functionality of validating IPv4 addresses.
    
    This class contains test methods to verify the correctness of IPv4 address validation logic,
    ensuring that valid IPv4 addresses are properly recognized and invalid ones are rejected.
    
    Attributes:
        None
    
    Methods:
        test_valid: Tests that the function correctly identifies a valid IPv4 address.
    Asserts that the string "8.8.8.8" is recognized as a valid IPv4 address. (default: "8.8.8.8")
        test_invalid: Verifies that a given value is not a valid IPv4 address.
    Args:
        value: The string or value to test for invalid IPv4 address format.
    """

    def test_valid(self):
        """
        Tests that the IPv4 validation function correctly identifies a valid IP address, ensuring robust input validation for network-related operations in the Requests library.
        
        This test verifies that the function properly recognizes standard IPv4 addresses like "8.8.8.8", which is essential for maintaining reliable and secure HTTP communication when resolving hostnames or validating network configurations in the library's internal operations.
        """
        assert is_ipv4_address("8.8.8.8")

    @pytest.mark.parametrize("value", ("8.8.8.8.8", "localhost.localdomain"))
    def test_invalid(self, value):
        """
        Verifies that a given value does not conform to a valid IPv4 address format, ensuring input validation for HTTP-related operations.
        
        Args:
            value: The string or value to test for invalid IPv4 address format.
        """
        assert not is_ipv4_address(value)


class TestIsValidCIDR:
    """
    Tests the validation of CIDR (Classless Inter-Domain Routing) notation.
    
    This class contains test methods to verify the correctness of CIDR address validation logic,
    ensuring that valid CIDR formats are accepted and invalid ones are rejected.
    
    Attributes:
        None
    
    Methods:
        test_valid: Tests that the is_valid_cidr function correctly identifies a valid CIDR notation.
                   Asserts that '192.168.1.0/24' is recognized as a valid CIDR address.
        test_invalid: Verifies that a given value is not a valid CIDR notation.
    Args:
        value: The string to test for invalid CIDR format.
    """

    def test_valid(self):
        """
        Tests that the is_valid_cidr function correctly validates proper CIDR notation, ensuring accurate network address validation within the Requests library's internal utilities.
        
        This validation is essential for maintaining robustness when handling network-related configurations, such as proxy settings or IP-based access controls, which may be used in advanced HTTP request scenarios involving network filtering or security policies.
        """
        assert is_valid_cidr("192.168.1.0/24")

    @pytest.mark.parametrize(
        "value",
        (
            "8.8.8.8",
            "192.168.1.0/a",
            "192.168.1.0/128",
            "192.168.1.0/-1",
            "192.168.1.999/24",
        ),
    )
    def test_invalid(self, value):
        """
        Verifies that a given value is not in valid CIDR notation to ensure network address validation in request configurations.
        
        Args:
            value: The string to test for invalid CIDR format, ensuring proper handling of IP range specifications in network-related request operations.
        """
        assert not is_valid_cidr(value)


class TestAddressInNetwork:
    """
    Tests the functionality of determining whether an IP address is within a specified network range.
    
        This class contains test methods to validate IP address inclusion in a network, ensuring correct network range evaluation.
    
        Attributes:
        - network: The network range in CIDR notation (e.g., '192.168.1.0/24') used for validation.
        - ip_address: The IP address to be tested for inclusion in the network.
    
        Methods:
        - test_valid: Tests that a given IP address is valid within a specified network range.
          Asserts that the IP address 192.168.1.1 is within the 192.168.1.0/24 network. (default: 192.168.1.0/24)
        - test_invalid: Verifies that an IP address outside the specified network range is correctly identified as not being in the network.
          Asserts that '172.16.0.1' is not within the '192.168.1.0/24' network, confirming proper network range validation. (default: no additional parameters)
    """

    def test_valid(self):
        """
        Tests that the IP address validation logic correctly identifies valid IP addresses within a network range.
        
        This test ensures the underlying network validation functionality works as expected, which is critical for features that rely on IP address filtering or access control—such as enforcing network boundaries in API request handling or security checks within the Requests library's extended use cases.
        """
        assert address_in_network("192.168.1.1", "192.168.1.0/24")

    def test_invalid(self):
        """
        Verifies correct network range validation by ensuring an IP address outside the specified subnet is properly identified as not belonging to it.
        
        This test ensures the underlying IP address validation logic works correctly, which is essential for features like network-based access control or routing decisions in HTTP clients that may need to validate client IP addresses against known networks. The test uses a known out-of-range IP ('172.16.0.1') and a specific network ('192.168.1.0/24') to confirm the function behaves as expected, supporting Requests' reliability in real-world network scenarios.
        """
        assert not address_in_network("172.16.0.1", "192.168.1.0/24")


class TestGuessFilename:
    """
    Tests the functionality of filename guessing based on object attributes.
    
        This class contains test methods to validate the behavior of a filename guessing mechanism,
        ensuring it correctly handles both valid and invalid inputs.
    
        Attributes:
            - value: The input value used for testing filename guessing.
            - expected_type: The expected type of the returned filename string in valid cases.
    
        Methods:
            - test_guess_filename_invalid: Tests that invalid input values result in None when guessing a filename.
            - test_guess_filename_valid: Tests that the filename is correctly guessed from an object's name attribute.
    """

    @pytest.mark.parametrize(
        "value",
        (1, type("Fake", (object,), {"name": 1})()),
    )
    def test_guess_filename_invalid(self, value):
        """
        Tests that invalid input values correctly result in None when guessing a filename, ensuring robust error handling in the filename inference logic.
        
        Args:
            value: The input value to test for filename guessing; expected to return None for invalid inputs to maintain reliability in HTTP response processing
        """
        assert guess_filename(value) is None

    @pytest.mark.parametrize(
        "value, expected_type",
        (
            (b"value", compat.bytes),
            (b"value".decode("utf-8"), compat.str),
        ),
    )
    def test_guess_filename_valid(self, value, expected_type):
        """
        Tests that the filename is correctly derived from an object's name attribute, ensuring consistent and predictable file naming in HTTP-related operations.
        
        Args:
            value: The name attribute value to test, expected to be used as the filename
            expected_type: The expected type of the returned filename string
        """
        obj = type("Fake", (object,), {"name": value})()
        result = guess_filename(obj)
        assert result == value
        assert isinstance(result, expected_type)


class TestExtractZippedPaths:
    """
    Tests the functionality of extracting zipped paths from file or directory paths.
    
        This class contains test methods to verify the behavior of path extraction logic, particularly focusing on handling zipped paths, unzipped paths, and invalid UNC paths. It ensures that paths are correctly processed or left unchanged based on their format.
    
        Class Methods:
        - test_unzipped_paths_unchanged: Verifies that the given path remains unchanged after extracting zipped paths.
        - test_zipped_paths_extracted: Tests that a zipped file path is correctly extracted to a temporary location.
        - test_invalid_unc_path: Tests that an invalid UNC path is returned unchanged when processed by extract_zipped_paths.
    """

    @pytest.mark.parametrize(
        "path",
        (
            "/",
            __file__,
            pytest.__file__,
            "/etc/invalid/location",
        ),
    )
    def test_unzipped_paths_unchanged(self, path):
        """
        Verifies that the original path is preserved after processing zipped path components, ensuring path normalization logic does not inadvertently alter intended paths.
        
        Args:
            path: The file or directory path to test. This check ensures that extracting zipped path segments (e.g., resolving `..` or `.` components) maintains the original path structure, which is critical for reliable file system operations in HTTP client workflows.
        """
        assert path == extract_zipped_paths(path)

    def test_zipped_paths_extracted(self, tmpdir):
        """
        Tests that a zipped file path is correctly extracted to a temporary location, ensuring the extracted file matches the original.
        
        This validation is critical for the Requests library's ability to handle compressed file downloads and extract them reliably, maintaining file integrity during HTTP operations involving zipped content.
        
        Args:
            tmpdir: Temporary directory fixture used to create and clean up test files.
        """
        zipped_py = tmpdir.join("test.zip")
        with zipfile.ZipFile(zipped_py.strpath, "w") as f:
            f.write(__file__)

        _, name = os.path.splitdrive(__file__)
        zipped_path = os.path.join(zipped_py.strpath, name.lstrip(r"\/"))
        extracted_path = extract_zipped_paths(zipped_path)

        assert extracted_path != zipped_path
        assert os.path.exists(extracted_path)
        assert filecmp.cmp(extracted_path, __file__)

    def test_invalid_unc_path(self):
        """
        Tests that malformed UNC paths are preserved unchanged by extract_zipped_paths, ensuring robust handling of invalid input formats. This behavior is critical in Requests' context to prevent unintended path manipulation when processing URLs or file paths, maintaining reliability and security in HTTP operations involving file system paths.
        """
        path = r"\\localhost\invalid\location"
        assert extract_zipped_paths(path) == path


class TestContentEncodingDetection:
    """
    Tests the content encoding detection functionality by validating how encoding declarations are parsed and prioritized in various contexts.
    
        The class verifies that encoding detection correctly identifies and respects encoding declarations such as pragmas, XML declarations, and HTML meta tags. It ensures proper precedence rules are applied when multiple encoding declarations are present, with later declarations overriding earlier ones where conflicts occur.
    
        Attributes:
        - content: The source code or document content to analyze for encoding declarations.
        - expected_encodings: The expected list of detected encodings based on the content's declared encodings.
    
        Methods:
        - test_none: Tests that an empty content string returns no encodings.
        - test_pragmas: Verifies that the given content contains exactly one encoding pragma, which must be UTF-8.
        - test_precedence: Tests that encoding detection respects the precedence of encoding declarations, with later declarations overriding earlier ones when there are conflicts. The XML declaration takes precedence over HTML meta tags, and the charset attribute in meta tags takes precedence over the content attribute value. (default: XML, HTML5, HTML4)
    """

    def test_none(self):
        """
        Tests that empty input content produces no encodings, ensuring robust handling of edge cases in text processing.
        
        This test verifies the expected behavior of get_encodings_from_content when provided with an empty string, which is critical for maintaining reliability in Requests' text handling pipeline. By confirming that empty input results in an empty encoding list, the function ensures consistent and safe processing of potentially null or empty responses from web services, aligning with Requests' goal of simplifying HTTP interactions while gracefully managing edge cases.
        """
        encodings = get_encodings_from_content("")
        assert not len(encodings)

    @pytest.mark.parametrize(
        "content",
        (
            # HTML5 meta charset attribute
            '<meta charset="UTF-8">',
            # HTML4 pragma directive
            '<meta http-equiv="Content-type" content="text/html;charset=UTF-8">',
            # XHTML 1.x served with text/html MIME type
            '<meta http-equiv="Content-type" content="text/html;charset=UTF-8" />',
            # XHTML 1.x served as XML
            '<?xml version="1.0" encoding="UTF-8"?>',
        ),
    )
    def test_pragmas(self, content):
        """
        Verifies that the source code contains exactly one encoding pragma, which must be UTF-8, to ensure consistent and correct text handling across all supported platforms and environments.
        
        Args:
            content: The source code content to analyze for encoding pragmas.
        """
        encodings = get_encodings_from_content(content)
        assert len(encodings) == 1
        assert encodings[0] == "UTF-8"

    def test_precedence(self):
        """
        Tests that encoding detection correctly prioritizes encoding declarations according to established precedence rules, ensuring accurate character encoding identification in mixed-content scenarios. This is critical for Requests' ability to reliably parse and decode responses from diverse web sources, maintaining data integrity across different HTML/XML formats and encoding declarations.
        """
        content = """
        <?xml version="1.0" encoding="XML"?>
        <meta charset="HTML5">
        <meta http-equiv="Content-type" content="text/html;charset=HTML4" />
        """.strip()
        assert get_encodings_from_content(content) == ["HTML5", "HTML4", "XML"]


class TestGuessJSONUTF:
    """
    Tests the functionality of the guess_json_utf function for detecting UTF encodings in JSON data.
    
        The class contains test methods to validate that the function correctly identifies various UTF encodings,
        including those specified via BOM (Byte Order Mark), and handles invalid or non-UTF-like byte sequences appropriately.
    
        Attributes:
            None explicitly defined in the constructor.
    
        Methods:
            test_encoded: Tests that the correct encoding is guessed for JSON data encoded with the specified encoding.
            test_bad_utf_like_encoding: Tests that invalid UTF-like encoding bytes are correctly identified as non-UTF by the guess_json_utf function.
            test_guess_by_bom: Tests UTF encoding detection based on BOM (Byte Order Mark).
    """

    @pytest.mark.parametrize(
        "encoding",
        (
            "utf-32",
            "utf-8-sig",
            "utf-16",
            "utf-8",
            "utf-16-be",
            "utf-16-le",
            "utf-32-be",
            "utf-32-le",
        ),
    )
    def test_encoded(self, encoding):
        """
        Tests that the JSON encoding detector correctly identifies the encoding of JSON data when explicitly encoded with a given charset.
        
        This ensures Requests can accurately parse JSON responses regardless of the underlying encoding, which is critical for reliable API interactions where server responses may use various encodings. The test validates the internal encoding detection logic by providing raw bytes with a known encoding and confirming the correct detection.
        
        Args:
            encoding: The encoding to test, such as 'utf-8', 'utf-16', etc.
        """
        data = "{}".encode(encoding)
        assert guess_json_utf(data) == encoding

    def test_bad_utf_like_encoding(self):
        """
        Tests that the guess_json_utf function correctly identifies invalid UTF-like byte sequences as non-UTF, ensuring robust handling of malformed or non-UTF data in JSON responses.
        
        This validation is critical for Requests' reliability when processing HTTP responses, as it prevents incorrect encoding assumptions that could lead to parsing errors or data corruption. By confirming that null bytes (which are not valid UTF-8) return None, the test ensures the library maintains safe defaults when encountering ambiguous or invalid encoding signals.
        """
        assert guess_json_utf(b"\x00\x00\x00\x00") is None

    @pytest.mark.parametrize(
        ("encoding", "expected"),
        (
            ("utf-16-be", "utf-16"),
            ("utf-16-le", "utf-16"),
            ("utf-32-be", "utf-32"),
            ("utf-32-le", "utf-32"),
        ),
    )
    def test_guess_by_bom(self, encoding, expected):
        """
        Tests the detection of UTF encodings when a BOM (Byte Order Mark) is present, ensuring correct handling of encoded JSON data.
        
        Args:
            encoding: The encoding of the input data, used to encode the test string with a BOM to simulate real-world scenarios where JSON content may be prefixed with a BOM.
            expected: The expected result from guess_json_utf when given the BOM-prefixed data, verifying that the function correctly identifies the encoding despite the BOM.
        """
        data = "\ufeff{}".encode(encoding)
        assert guess_json_utf(data) == expected


USER = PASSWORD = "%!*'();:@&=+$,/?#[] "
ENCODED_USER = compat.quote(USER, "")
ENCODED_PASSWORD = compat.quote(PASSWORD, "")


@pytest.mark.parametrize(
    "url, auth",
    (
        (
            f"http://{ENCODED_USER}:{ENCODED_PASSWORD}@request.com/url.html#test",
            (USER, PASSWORD),
        ),
        ("http://user:pass@complex.url.com/path?query=yes", ("user", "pass")),
        (
            "http://user:pass%20pass@complex.url.com/path?query=yes",
            ("user", "pass pass"),
        ),
        ("http://user:pass pass@complex.url.com/path?query=yes", ("user", "pass pass")),
        (
            "http://user%25user:pass@complex.url.com/path?query=yes",
            ("user%user", "pass"),
        ),
        (
            "http://user:pass%23pass@complex.url.com/path?query=yes",
            ("user", "pass#pass"),
        ),
        ("http://complex.url.com/path?query=yes", ("", "")),
    ),
)
def test_get_auth_from_url(url, auth):
    """
    Verifies that the get_auth_from_url function accurately extracts authentication credentials from URLs, ensuring proper handling of credentials in HTTP requests. This test supports Requests' goal of simplifying HTTP interactions by validating that authentication details are correctly parsed from URLs, which is essential for secure and reliable request authentication.
    
    Args:
        url: The URL string to parse for authentication details
        auth: The expected authentication tuple (username, password) that should be returned by get_auth_from_url
    """
    assert get_auth_from_url(url) == auth


@pytest.mark.parametrize(
    "uri, expected",
    (
        (
            # Ensure requoting doesn't break expectations
            "http://example.com/fiz?buz=%25ppicture",
            "http://example.com/fiz?buz=%25ppicture",
        ),
        (
            # Ensure we handle unquoted percent signs in redirects
            "http://example.com/fiz?buz=%ppicture",
            "http://example.com/fiz?buz=%25ppicture",
        ),
    ),
)
def test_requote_uri_with_unquoted_percents(uri, expected):
    """
    Tests the requote_uri function's handling of unquoted percent characters in URIs, ensuring correct encoding behavior for compatibility with HTTP standards and consistent URL processing.
    
    Args:
        uri: The input URI string containing unquoted percent characters to be tested.
        expected: The expected output after re-quoting the URI, representing the correct encoding behavior.
    """
    assert requote_uri(uri) == expected


@pytest.mark.parametrize(
    "uri, expected",
    (
        (
            # Illegal bytes
            "http://example.com/?a=%--",
            "http://example.com/?a=%--",
        ),
        (
            # Reserved characters
            "http://example.com/?a=%300",
            "http://example.com/?a=00",
        ),
    ),
)
def test_unquote_unreserved(uri, expected):
    """
    Test that unquoting unreserved characters in a URI produces the expected result, ensuring correct handling of URI components during request construction.
    
    Args:
        uri: The URI string containing percent-encoded unreserved characters to be unquoted.
        expected: The expected string result after unquoting unreserved characters.
    """
    assert unquote_unreserved(uri) == expected


@pytest.mark.parametrize(
    "mask, expected",
    (
        (8, "255.0.0.0"),
        (24, "255.255.255.0"),
        (25, "255.255.255.128"),
    ),
)
def test_dotted_netmask(mask, expected):
    """
    Tests that the dotted netmask conversion function correctly transforms input values into their expected dotted decimal string representation.
    
    This validation ensures accurate network mask handling within the library's networking utilities, supporting reliable IP address and subnet calculations essential for network-related operations in HTTP client interactions.
    
    Args:
        mask: The netmask value to convert, either as an integer or a string representation.
        expected: The expected dotted decimal string representation of the netmask.
    """
    assert dotted_netmask(mask) == expected


http_proxies = {
    "http": "http://http.proxy",
    "http://some.host": "http://some.host.proxy",
}
all_proxies = {
    "all": "socks5://http.proxy",
    "all://some.host": "socks5://some.host.proxy",
}
mixed_proxies = {
    "http": "http://http.proxy",
    "http://some.host": "http://some.host.proxy",
    "all": "socks5://http.proxy",
}


@pytest.mark.parametrize(
    "url, expected, proxies",
    (
        ("hTTp://u:p@Some.Host/path", "http://some.host.proxy", http_proxies),
        ("hTTp://u:p@Other.Host/path", "http://http.proxy", http_proxies),
        ("hTTp:///path", "http://http.proxy", http_proxies),
        ("hTTps://Other.Host", None, http_proxies),
        ("file:///etc/motd", None, http_proxies),
        ("hTTp://u:p@Some.Host/path", "socks5://some.host.proxy", all_proxies),
        ("hTTp://u:p@Other.Host/path", "socks5://http.proxy", all_proxies),
        ("hTTp:///path", "socks5://http.proxy", all_proxies),
        ("hTTps://Other.Host", "socks5://http.proxy", all_proxies),
        ("http://u:p@other.host/path", "http://http.proxy", mixed_proxies),
        ("http://u:p@some.host/path", "http://some.host.proxy", mixed_proxies),
        ("https://u:p@other.host/path", "socks5://http.proxy", mixed_proxies),
        ("https://u:p@some.host/path", "socks5://http.proxy", mixed_proxies),
        ("https://", "socks5://http.proxy", mixed_proxies),
        # XXX: unsure whether this is reasonable behavior
        ("file:///etc/motd", "socks5://http.proxy", all_proxies),
    ),
)
def test_select_proxies(url, expected, proxies):
    """
    Verify that the proxy selection logic correctly routes requests to the appropriate proxy based on the host.
    
    This test ensures that the `select_proxy` function properly matches URLs to their corresponding per-host proxies, which is essential for maintaining secure and controlled network access in environments where different hosts require different proxy configurations. This functionality supports the Requests library's goal of providing flexible and reliable HTTP communication, especially in complex network setups involving multiple proxy servers.
    
    Args:
        url: The URL to test proxy selection for, used to determine the target host.
        expected: The expected proxy configuration that should be returned for the given URL.
        proxies: A dictionary mapping host patterns to proxy URLs, used to define per-host proxy rules.
    """
    assert select_proxy(url, proxies) == expected


@pytest.mark.parametrize(
    "value, expected",
    (
        ('foo="is a fish", bar="as well"', {"foo": "is a fish", "bar": "as well"}),
        ("key_without_value", {"key_without_value": None}),
    ),
)
def test_parse_dict_header(value, expected):
    """
    Tests that the dictionary header parsing function correctly converts a header string into a dictionary, ensuring accurate handling of HTTP headers in Requests' internal processing.
    
    Args:
        value: The header string to parse, typically in the format "key1=value1; key2=value2", representing structured HTTP header data
        expected: The dictionary result that should be produced by parsing the header string, used to validate correct behavior
    """
    assert parse_dict_header(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    (
        ("application/xml", ("application/xml", {})),
        (
            "application/json ; charset=utf-8",
            ("application/json", {"charset": "utf-8"}),
        ),
        (
            "application/json ; Charset=utf-8",
            ("application/json", {"charset": "utf-8"}),
        ),
        ("text/plain", ("text/plain", {})),
        (
            "multipart/form-data; boundary = something ; boundary2='something_else' ; no_equals ",
            (
                "multipart/form-data",
                {
                    "boundary": "something",
                    "boundary2": "something_else",
                    "no_equals": True,
                },
            ),
        ),
        (
            'multipart/form-data; boundary = something ; boundary2="something_else" ; no_equals ',
            (
                "multipart/form-data",
                {
                    "boundary": "something",
                    "boundary2": "something_else",
                    "no_equals": True,
                },
            ),
        ),
        (
            "multipart/form-data; boundary = something ; 'boundary2=something_else' ; no_equals ",
            (
                "multipart/form-data",
                {
                    "boundary": "something",
                    "boundary2": "something_else",
                    "no_equals": True,
                },
            ),
        ),
        (
            'multipart/form-data; boundary = something ; "boundary2=something_else" ; no_equals ',
            (
                "multipart/form-data",
                {
                    "boundary": "something",
                    "boundary2": "something_else",
                    "no_equals": True,
                },
            ),
        ),
        ("application/json ; ; ", ("application/json", {})),
    ),
)
def test__parse_content_type_header(value, expected):
    """
    Tests the internal parsing of Content-Type header strings to ensure correct extraction of media type and parameters, which is essential for proper request and response handling in HTTP communication.
    
    Args:
        value: The raw Content-Type header string to parse, representing the media type and optional parameters (e.g., 'application/json; charset=utf-8')
        expected: The expected result after parsing, typically a tuple of (media_type, parameters), used to validate the correctness of the parser
    """
    assert _parse_content_type_header(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    (
        (CaseInsensitiveDict(), None),
        (
            CaseInsensitiveDict({"content-type": "application/json; charset=utf-8"}),
            "utf-8",
        ),
        (CaseInsensitiveDict({"content-type": "text/plain"}), "ISO-8859-1"),
    ),
)
def test_get_encoding_from_headers(value, expected):
    """
    Tests that the encoding detection from HTTP headers correctly identifies the expected character encoding, ensuring accurate text decoding in HTTP responses. This validation is critical for Requests' core functionality of reliably handling diverse web content across different encodings.
    
    Args:
        value: Dictionary containing HTTP headers to test encoding extraction from
        expected: The expected encoding string that should be returned by get_encoding_from_headers
    """
    assert get_encoding_from_headers(value) == expected


@pytest.mark.parametrize(
    "value, length",
    (
        ("", 0),
        ("T", 1),
        ("Test", 4),
        ("Cont", 0),
        ("Other", -5),
        ("Content", None),
    ),
)
def test_iter_slices(value, length):
    """
    Tests the behavior of iter_slices function to ensure it correctly handles different slice configurations, which is essential for efficient chunked processing of large data streams in HTTP requests.
    
    Args:
        value: The input iterable to be sliced, typically representing data received from an HTTP response
        length: The desired number of slices; if None or non-positive, tests reading all content at once to verify fallback behavior
    """
    if length is None or (length <= 0 and len(value) > 0):
        # Reads all content at once
        assert len(list(iter_slices(value, length))) == 1
    else:
        assert len(list(iter_slices(value, 1))) == length


@pytest.mark.parametrize(
    "value, expected",
    (
        (
            '<http:/.../front.jpeg>; rel=front; type="image/jpeg"',
            [{"url": "http:/.../front.jpeg", "rel": "front", "type": "image/jpeg"}],
        ),
        ("<http:/.../front.jpeg>", [{"url": "http:/.../front.jpeg"}]),
        ("<http:/.../front.jpeg>;", [{"url": "http:/.../front.jpeg"}]),
        (
            '<http:/.../front.jpeg>; type="image/jpeg",<http://.../back.jpeg>;',
            [
                {"url": "http:/.../front.jpeg", "type": "image/jpeg"},
                {"url": "http://.../back.jpeg"},
            ],
        ),
        ("", []),
    ),
)
def test_parse_header_links(value, expected):
    """
    Tests that the header link parsing function correctly interprets HTTP Link header values according to the standard format, ensuring accurate extraction of URLs and their associated parameters for proper request handling.
    
    Args:
        value: The header value string to parse, typically in the format used by HTTP Link headers.
        expected: The expected list of dictionaries representing parsed link information, including 'url' and optional 'params'.
    """
    assert parse_header_links(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    (
        ("example.com/path", "http://example.com/path"),
        ("//example.com/path", "http://example.com/path"),
        ("example.com:80", "http://example.com:80"),
        (
            "http://user:pass@example.com/path?query",
            "http://user:pass@example.com/path?query",
        ),
        ("http://user@example.com/path?query", "http://user@example.com/path?query"),
    ),
)
def test_prepend_scheme_if_needed(value, expected):
    """
    Tests that a URL scheme is automatically prepended with 'http' when missing, ensuring consistent URL formatting for reliable HTTP requests.
    
    Args:
        value: The URL string to test, which may or may not include a scheme
        expected: The expected result after scheme prepending if needed
    """
    assert prepend_scheme_if_needed(value, "http") == expected


@pytest.mark.parametrize(
    "value, expected",
    (
        ("T", "T"),
        (b"T", "T"),
        ("T", "T"),
    ),
)
def test_to_native_string(value, expected):
    """
    Tests that the to_native_string function correctly converts various input types to their native string representation, ensuring consistent string handling across different data types in the Requests library.
    
    Args:
        value: The input value to convert to a native string, representing diverse data types that may be encountered during HTTP request processing
        expected: The expected string output after conversion, used to verify correct behavior for edge cases and type normalization
    """
    assert to_native_string(value) == expected


@pytest.mark.parametrize(
    "url, expected",
    (
        ("http://u:p@example.com/path?a=1#test", "http://example.com/path?a=1"),
        ("http://example.com/path", "http://example.com/path"),
        ("//u:p@example.com/path", "//example.com/path"),
        ("//example.com/path", "//example.com/path"),
        ("example.com/path", "//example.com/path"),
        ("scheme:u:p@example.com/path", "scheme://example.com/path"),
    ),
)
def test_urldefragauth(url, expected):
    """
    Test that urldefragauth correctly extracts authentication credentials from URLs, ensuring proper handling of user and password information in request URLs.
    
    Args:
        url: The URL string to parse, expected to contain authentication information in the format 'scheme://user:password@host'.
        expected: The expected result after extracting the authentication part, typically a tuple of (user, password).
    """
    assert urldefragauth(url) == expected


@pytest.mark.parametrize(
    "url, expected",
    (
        ("http://192.168.0.1:5000/", True),
        ("http://192.168.0.1/", True),
        ("http://172.16.1.1/", True),
        ("http://172.16.1.1:5000/", True),
        ("http://localhost.localdomain:5000/v1.0/", True),
        ("http://google.com:6000/", True),
        ("http://172.16.1.12/", False),
        ("http://172.16.1.12:5000/", False),
        ("http://google.com:5000/v1.0/", False),
        ("file:///some/path/on/disk", True),
    ),
)
def test_should_bypass_proxies(url, expected, monkeypatch):
    """
    Tests the behavior of should_bypass_proxies by verifying whether a given URL should bypass proxy settings based on the no_proxy environment variable. This ensures that requests to specific hosts or networks (like localhost or internal IPs) are handled correctly without going through proxies, which is essential for secure and efficient HTTP communication in the Requests library.
    
    Args:
        url: The URL to test for proxy bypassing.
        expected: The expected boolean result indicating whether the proxy should be bypassed.
        monkeypatch: Fixture to temporarily modify environment variables during the test.
    """
    monkeypatch.setenv(
        "no_proxy",
        "192.168.0.0/24,127.0.0.1,localhost.localdomain,172.16.1.1, google.com:6000",
    )
    monkeypatch.setenv(
        "NO_PROXY",
        "192.168.0.0/24,127.0.0.1,localhost.localdomain,172.16.1.1, google.com:6000",
    )
    assert should_bypass_proxies(url, no_proxy=None) == expected


@pytest.mark.parametrize(
    "url, expected",
    (
        ("http://172.16.1.1/", "172.16.1.1"),
        ("http://172.16.1.1:5000/", "172.16.1.1"),
        ("http://user:pass@172.16.1.1", "172.16.1.1"),
        ("http://user:pass@172.16.1.1:5000", "172.16.1.1"),
        ("http://hostname/", "hostname"),
        ("http://hostname:5000/", "hostname"),
        ("http://user:pass@hostname", "hostname"),
        ("http://user:pass@hostname:5000", "hostname"),
    ),
)
def test_should_bypass_proxies_pass_only_hostname(url, expected):
    """
    Tests that the proxy bypass logic correctly handles a hostname without port or credentials, ensuring requests are routed appropriately when no_proxy is not specified.
    
    Args:
        url: The URL to test, containing only a hostname or IP address without port or authentication details.
        expected: The expected value passed to the proxy_bypass function, used to verify correct behavior.
    """
    with mock.patch("requests.utils.proxy_bypass") as proxy_bypass:
        should_bypass_proxies(url, no_proxy=None)
        proxy_bypass.assert_called_once_with(expected)


@pytest.mark.parametrize(
    "cookiejar",
    (
        compat.cookielib.CookieJar(),
        RequestsCookieJar(),
    ),
)
def test_add_dict_to_cookiejar(cookiejar):
    """
    Verify that add_dict_to_cookiejar correctly handles non-RequestsCookieJar cookie jars, ensuring compatibility with custom or alternative cookie storage implementations.
    
    Args:
        cookiejar: A cookie jar instance that is not a RequestsCookieJar, used to test the function's ability to work with alternative cookie storage backends.
    """
    cookiedict = {"test": "cookies", "good": "cookies"}
    cj = add_dict_to_cookiejar(cookiejar, cookiedict)
    cookies = {cookie.name: cookie.value for cookie in cj}
    assert cookiedict == cookies


@pytest.mark.parametrize(
    "value, expected",
    (
        ("test", True),
        ("æíöû", False),
        ("ジェーピーニック", False),
    ),
)
def test_unicode_is_ascii(value, expected):
    """
    Tests whether a Unicode string consists solely of ASCII characters, ensuring data integrity in HTTP operations.
    
    Args:
        value: The Unicode string to test for ASCII characters only.
        expected: The expected boolean result indicating if the string is ASCII.
    """
    assert unicode_is_ascii(value) is expected


@pytest.mark.parametrize(
    "url, expected",
    (
        ("http://192.168.0.1:5000/", True),
        ("http://192.168.0.1/", True),
        ("http://172.16.1.1/", True),
        ("http://172.16.1.1:5000/", True),
        ("http://localhost.localdomain:5000/v1.0/", True),
        ("http://172.16.1.12/", False),
        ("http://172.16.1.12:5000/", False),
        ("http://google.com:5000/v1.0/", False),
    ),
)
def test_should_bypass_proxies_no_proxy(url, expected, monkeypatch):
    """
    Tests the behavior of should_bypass_proxies when determining whether a URL should skip proxy usage based on the no_proxy configuration. This ensures that requests to specific domains or IP ranges (like local networks or localhost) are not routed through proxies, which is essential for maintaining security and performance in local development and internal network scenarios.
    
    Args:
        url: The URL to test for proxy bypassing.
        expected: The expected boolean result indicating whether the proxy should be bypassed.
        monkeypatch: Fixture to temporarily modify behavior during the test, used here to isolate the test environment.
    """
    no_proxy = "192.168.0.0/24,127.0.0.1,localhost.localdomain,172.16.1.1"
    # Test 'no_proxy' argument
    assert should_bypass_proxies(url, no_proxy=no_proxy) == expected


@pytest.mark.skipif(os.name != "nt", reason="Test only on Windows")
@pytest.mark.parametrize(
    "url, expected, override",
    (
        ("http://192.168.0.1:5000/", True, None),
        ("http://192.168.0.1/", True, None),
        ("http://172.16.1.1/", True, None),
        ("http://172.16.1.1:5000/", True, None),
        ("http://localhost.localdomain:5000/v1.0/", True, None),
        ("http://172.16.1.22/", False, None),
        ("http://172.16.1.22:5000/", False, None),
        ("http://google.com:5000/v1.0/", False, None),
        ("http://mylocalhostname:5000/v1.0/", True, "<local>"),
        ("http://192.168.0.1/", False, ""),
    ),
)
def test_should_bypass_proxies_win_registry(url, expected, override, monkeypatch):
    """
    Tests the behavior of should_bypass_proxies when determining whether a URL should bypass proxies based on Windows registry settings, ensuring correct proxy bypass logic for applications using Requests on Windows systems.
    
    Args:
        url: The URL to test for proxy bypass behavior.
        expected: The expected result (True or False) indicating whether the proxy should be bypassed.
        override: The proxy override string from the Windows registry, or None to use a default value.
        monkeypatch: Fixture to temporarily modify behavior during testing.
    
    Returns:
        None; the test asserts that should_bypass_proxies returns the expected result for the given URL and registry configuration.
    """
    if override is None:
        override = "192.168.*;127.0.0.1;localhost.localdomain;172.16.1.1"
    import winreg

    class RegHandle:
        def Close(self):
            pass

    ie_settings = RegHandle()
    proxyEnableValues = deque([1, "1"])

    def OpenKey(key, subkey):
        return ie_settings

    def QueryValueEx(key, value_name):
        if key is ie_settings:
            if value_name == "ProxyEnable":
                # this could be a string (REG_SZ) or a 32-bit number (REG_DWORD)
                proxyEnableValues.rotate()
                return [proxyEnableValues[0]]
            elif value_name == "ProxyOverride":
                return [override]

    monkeypatch.setenv("http_proxy", "")
    monkeypatch.setenv("https_proxy", "")
    monkeypatch.setenv("ftp_proxy", "")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setattr(winreg, "OpenKey", OpenKey)
    monkeypatch.setattr(winreg, "QueryValueEx", QueryValueEx)
    assert should_bypass_proxies(url, None) == expected


@pytest.mark.skipif(os.name != "nt", reason="Test only on Windows")
def test_should_bypass_proxies_win_registry_bad_values(monkeypatch):
    """
    Tests the behavior of should_bypass_proxies when Windows Internet Explorer proxy settings contain invalid values, ensuring the function correctly handles malformed registry data without failing.
    
    Args:
        monkeypatch: pytest fixture used to mock Windows registry functions and environment variables.
    
    Returns:
        Asserts that the function returns False when attempting to bypass proxies for a URL matching a bypass list, even when the ProxyEnable value is invalid (non-integer), confirming robustness against malformed registry configurations in the Requests library's proxy detection logic.
    """
    import winreg

    class RegHandle:
        def Close(self):
            pass

    ie_settings = RegHandle()

    def OpenKey(key, subkey):
        return ie_settings

    def QueryValueEx(key, value_name):
        if key is ie_settings:
            if value_name == "ProxyEnable":
                # Invalid response; Should be an int or int-y value
                return [""]
            elif value_name == "ProxyOverride":
                return ["192.168.*;127.0.0.1;localhost.localdomain;172.16.1.1"]

    monkeypatch.setenv("http_proxy", "")
    monkeypatch.setenv("https_proxy", "")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setattr(winreg, "OpenKey", OpenKey)
    monkeypatch.setattr(winreg, "QueryValueEx", QueryValueEx)
    assert should_bypass_proxies("http://172.16.1.1/", None) is False


@pytest.mark.parametrize(
    "env_name, value",
    (
        ("no_proxy", "192.168.0.0/24,127.0.0.1,localhost.localdomain"),
        ("no_proxy", None),
        ("a_new_key", "192.168.0.0/24,127.0.0.1,localhost.localdomain"),
        ("a_new_key", None),
    ),
)
def test_set_environ(env_name, value):
    """
    Tests that set_environ correctly modifies environment variables during execution and restores the original state afterward, ensuring test isolation and preventing side effects in the test suite.
    
    Args:
        env_name: The name of the environment variable to set.
        value: The value to assign to the environment variable during the test.
    """
    environ_copy = copy.deepcopy(os.environ)
    with set_environ(env_name, value):
        assert os.environ.get(env_name) == value

    assert os.environ == environ_copy


def test_set_environ_raises_exception():
    """
    Verifies that set_environ raises an exception when given a None value, ensuring environment variable safety during HTTP operations.
    
    This test is critical for Requests' reliability: it confirms that invalid environment configurations (like setting a variable to None) are caught early, preventing unintended behavior in HTTP requests that depend on environment variables. By validating this behavior, the test helps maintain the library's goal of providing a robust, predictable interface for HTTP interactions.
    """
    with pytest.raises(Exception) as exception:
        with set_environ("test1", None):
            raise Exception("Expected exception")

    assert "Expected exception" in str(exception.value)


@pytest.mark.skipif(os.name != "nt", reason="Test only on Windows")
def test_should_bypass_proxies_win_registry_ProxyOverride_value(monkeypatch):
    """
    Tests whether the proxy should be bypassed for a given URL when using Windows' ProxyOverride registry setting that ends with a semicolon.
    
    This test verifies the correct handling of proxy bypass logic in the `should_bypass_proxies` function, ensuring that URLs matching patterns in the ProxyOverride value (including those with trailing semicolons) are properly excluded from proxy usage. This is critical for Requests' ability to correctly respect system-level proxy configurations on Windows, especially in environments where local or internal addresses should not go through a proxy.
    
    Args:
        monkeypatch: pytest fixture to temporarily replace functions or attributes for testing
    
    Returns:
        True if the proxy should be bypassed, False otherwise
    """
    import winreg

    class RegHandle:
        def Close(self):
            pass

    ie_settings = RegHandle()

    def OpenKey(key, subkey):
        return ie_settings

    def QueryValueEx(key, value_name):
        if key is ie_settings:
            if value_name == "ProxyEnable":
                return [1]
            elif value_name == "ProxyOverride":
                return [
                    "192.168.*;127.0.0.1;localhost.localdomain;172.16.1.1;<-loopback>;"
                ]

    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setattr(winreg, "OpenKey", OpenKey)
    monkeypatch.setattr(winreg, "QueryValueEx", QueryValueEx)
    assert should_bypass_proxies("http://example.com/", None) is False
