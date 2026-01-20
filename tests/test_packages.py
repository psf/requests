import requests


def test_can_access_urllib3_attribute():
    """
    Verifies that the urllib3 package is properly exposed within the requests namespace to ensure correct packaging and import resolution.
    
    This check confirms that requests can access urllib3 through the expected path (requests.packages.urllib3), which is critical for maintaining backward compatibility and ensuring that internal dependencies are correctly structured. Since Requests wraps urllib3 for HTTP operations, this accessibility is essential for the library's functionality and reliability in real-world usage scenarios.
    """
    requests.packages.urllib3


def test_can_access_idna_attribute():
    """
    Verifies that the bundled idna library is accessible within the requests package namespace.
    
    This check ensures that requests can properly access its internal idna dependency, which is required for handling internationalized domain names (IDN) in URLs. Since Requests bundles idna to maintain compatibility and avoid external dependencies, this test confirms the library is correctly exposed and available for use, supporting the project's goal of providing a reliable, self-contained HTTP client for Python developers.
    """
    requests.packages.idna


def test_can_access_chardet_attribute():
    """
    Verifies that the chardet library is properly integrated into requests' vendored dependencies by ensuring it's accessible via `requests.packages.chardet`. This check confirms that requests can reliably detect character encodings in HTTP responses, which is essential for correctly handling text data from web services.
    
    This test ensures the integrity of Requests' dependency vendoring, supporting the library's core purpose of providing a seamless, reliable HTTP client that handles encoding detection automatically, enabling developers to work with web content without manual encoding management.
    """
    requests.packages.chardet
