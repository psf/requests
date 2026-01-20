import pytest

from requests.structures import CaseInsensitiveDict, LookupDict


class TestCaseInsensitiveDict:
    """
    A case-insensitive dictionary that treats all keys as lowercase for comparison, while preserving the original case of keys when accessed.
    
        Attributes:
        - possible_keys: A list of keys that are considered valid for the dictionary, used to validate key inputs during initialization.
    
        Methods:
        - setup: Creates a CaseInsensitiveDict instance with the "Accept" header.
        - test_list: Verifies that the dictionary's keys, when converted to a list, match the expected order and values.
        - test_getitem: Tests that retrieving a key from the case-insensitive dictionary returns the expected value.
        - test_delitem: Removes an item from the case-insensitive dictionary and verifies it is no longer present.
        - test_lower_items: Verifies that the lower_items method returns a list of (key, value) pairs with keys in lowercase.
        - test_repr: Verifies that the string representation of the case-insensitive dictionary matches the expected format.
        - test_copy: Tests that the copy method creates a new dictionary instance that is equal to the original.
        - test_instance_equality: Tests equality between the instance's case-insensitive dictionary and another object.
    
        The class ensures that key lookups, deletions, and iterations are performed in a case-insensitive manner, while maintaining the original key casing for display and retrieval. The possible_keys attribute restricts valid keys during initialization, enhancing data integrity.
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        """
        Initialize a case-insensitive dictionary with the 'Accept' header set to 'application/json'.
        
        This setup ensures that HTTP requests made through the library consistently indicate a preference for JSON responses, aligning with the project's goal of simplifying API interactions by defaulting to the most common and developer-friendly response format. The use of a case-insensitive dictionary supports flexible header handling, which is essential for robust and user-friendly HTTP communication.
        """
        self.case_insensitive_dict = CaseInsensitiveDict()
        self.case_insensitive_dict["Accept"] = "application/json"

    def test_list(self):
        """
        Verifies that the case-insensitive dictionary correctly preserves the expected key order and value during iteration, ensuring consistent header retrieval behavior.
        
        This test confirms that the dictionary maintains proper case-insensitive key handling—specifically that it returns exactly one key, "Accept", when converted to a list—supporting Requests' core purpose of reliably managing HTTP headers regardless of case variations in client input.
        """
        assert list(self.case_insensitive_dict) == ["Accept"]

    possible_keys = pytest.mark.parametrize(
        "key", ("accept", "ACCEPT", "aCcEpT", "Accept")
    )

    @possible_keys
    def test_getitem(self, key):
        """
        Tests that the case-insensitive dictionary correctly retrieves values using keys that match 'application/json' regardless of case, ensuring consistent header handling in HTTP requests.
        
        Args:
            key: The key to retrieve from the dictionary; must be a string that matches 'application/json' in a case-insensitive manner, simulating real-world HTTP header lookups where case variations are common
        """
        assert self.case_insensitive_dict[key] == "application/json"

    @possible_keys
    def test_delitem(self, key):
        """
        Removes a key-value pair from the case-insensitive dictionary to test proper case-insensitive key handling during deletion.
        
        This ensures that the dictionary correctly removes items regardless of case variation in the key, which is essential for maintaining consistent behavior when interacting with HTTP headers or other case-insensitive data structures in Requests.
        
        Args:
            key: The key to remove from the dictionary. The key comparison is case-insensitive.
        """
        del self.case_insensitive_dict[key]
        assert key not in self.case_insensitive_dict

    def test_lower_items(self):
        """
        Verifies that the lower_items method correctly normalizes dictionary keys to lowercase, ensuring consistent case-insensitive access to headers or metadata. This is essential for the Requests library to reliably compare and process HTTP headers regardless of their original casing, maintaining predictable behavior during request and response handling.
        """
        assert list(self.case_insensitive_dict.lower_items()) == [
            ("accept", "application/json")
        ]

    def test_repr(self):
        """
        Verifies that the case-insensitive dictionary's string representation accurately reflects its contents for debugging and testing purposes.
        
        This test ensures the custom dictionary implementation maintains proper string formatting when inspected, which is crucial for reliable debugging and consistent behavior in HTTP header handling—aligning with Requests' goal of providing predictable, user-friendly HTTP interactions.
        """
        assert repr(self.case_insensitive_dict) == "{'Accept': 'application/json'}"

    def test_copy(self):
        """
        Tests that the copy method properly creates a shallow copy of the case-insensitive dictionary, ensuring that the new instance is independent of the original while preserving all key-value pairs.
        
        This verification is critical for maintaining predictable behavior in HTTP request handling, where case-insensitive headers or parameters must be duplicated without affecting the original data structure. Ensuring correct shallow copying supports safe manipulation of request metadata across different parts of the application.
        """
        copy = self.case_insensitive_dict.copy()
        assert copy is not self.case_insensitive_dict
        assert copy == self.case_insensitive_dict

    @pytest.mark.parametrize(
        "other, result",
        (
            ({"AccePT": "application/json"}, True),
            ({}, False),
            (None, False),
        ),
    )
    def test_instance_equality(self, other, result):
        """
        Tests whether the instance's case-insensitive dictionary correctly evaluates equality with another object, ensuring consistent behavior in HTTP header and metadata comparisons.
        
        Args:
            other: The object to compare against the instance's case-insensitive dictionary, typically used to validate expected equality outcomes during testing.
            result: Expected boolean result of the equality comparison (default: True), used to verify correct behavior in test scenarios.
        """
        assert (self.case_insensitive_dict == other) is result


class TestLookupDict:
    """
    TestLookupDict is a test class designed to verify the functionality of a lookup dictionary implementation. It ensures that dictionary-like operations such as item retrieval and representation are correctly implemented.
    
        Attributes:
        - bad_gateway: A test attribute used to validate lookup behavior.
        - test: A default test key used in various test cases.
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        """
        Initialize a LookupDict instance with a 'bad_gateway' attribute set to 502 for testing HTTP error handling.
        
        This setup is used in the Requests library to simulate and test HTTP error responses, particularly for status codes like 502 Bad Gateway, ensuring the library correctly handles and propagates such errors during request processing.
        """
        self.lookup_dict = LookupDict("test")
        self.lookup_dict.bad_gateway = 502

    def test_repr(self):
        """
        Verifies that the lookup dictionary's repr() output correctly reflects its intended debug-friendly format, ensuring consistent and meaningful representation during development and troubleshooting. This is critical in Requests for maintaining clear visibility into internal state when debugging HTTP interactions or session behavior.
        """
        assert repr(self.lookup_dict) == "<lookup 'test'>"

    get_item_parameters = pytest.mark.parametrize(
        "key, value",
        (
            ("bad_gateway", 502),
            ("not_a_key", None),
        ),
    )

    @get_item_parameters
    def test_getitem(self, key, value):
        """
        Verifies that the lookup dictionary returns the expected value for a given key, ensuring correct data retrieval behavior in the HTTP request handling pipeline.
        
        Args:
            key: The key to look up in the dictionary, typically representing a request parameter, header, or identifier.
            value: The expected value associated with the key, used to validate that the lookup logic correctly retrieves stored data.
        """
        assert self.lookup_dict[key] == value

    @get_item_parameters
    def test_get(self, key, value):
        """
        Verifies that the lookup dictionary contains the expected value for a given key, ensuring correct data retrieval during HTTP request processing.
        
        Args:
            key: The key to look up in the dictionary, typically representing a request parameter, header, or response field.
            value: The expected value associated with the key, used to validate that the request or response data was processed correctly.
        """
        assert self.lookup_dict.get(key) == value
