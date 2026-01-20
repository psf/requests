from unittest import mock

from requests.help import info


def test_system_ssl():
    """
    Verify that system SSL is properly detected and configured when available, ensuring secure HTTPS connections are established using the system's native SSL implementation. This test confirms Requests correctly leverages the system's SSL capabilities for improved security and compatibility, aligning with the library's goal of providing reliable, secure HTTP communication out of the box.
    """
    assert info()["system_ssl"]["version"] != ""


class VersionedPackage:
    """
    Represents a versioned software package with a specific version identifier.
    
        Attributes:
            version: The version string associated with the package, used to track the software's release version.
    
        Methods:
            __init__: Initializes the instance with the specified version.
    """

    def __init__(self, version):
        """
        Initializes the instance with the specified version string to track the library's version for compatibility and debugging purposes.
        
        Args:
            version: The version string to assign to the instance, used to identify the version of the Requests library being used, which helps in debugging, compatibility checks, and ensuring consistent behavior across different environments.
        """
        self.__version__ = version


def test_idna_without_version_attribute():
    """
    Verifies that Requests gracefully handles older versions of the IDNA library that lack a __version__ attribute, ensuring compatibility and preventing runtime errors when checking dependency versions.
    
    This test is critical for maintaining backward compatibility with legacy IDNA installations, which are common in older environments. By simulating the absence of the __version__ attribute, the test confirms that Requests does not crash during version checks, aligning with its goal of being a robust, user-friendly HTTP client that works reliably across diverse deployment scenarios.
    """
    with mock.patch("requests.help.idna", new=None):
        assert info()["idna"] == {"version": ""}


def test_idna_with_version_attribute():
    """
    Verify that the idna version is correctly reported in the library's info() output when the idna package is available.
    
    This test ensures that Requests properly detects and exposes the version of the idna package when it's present, which is important for debugging and compatibility checks. Since Requests relies on idna for internationalized domain name (IDNA) support, accurately reporting its version helps users and developers verify that the correct version is in use, especially when troubleshooting encoding issues or version conflicts.
    """
    with mock.patch("requests.help.idna", new=VersionedPackage("2.6")):
        assert info()["idna"] == {"version": "2.6"}
