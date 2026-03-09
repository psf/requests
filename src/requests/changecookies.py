from collections.abc import MutableMapping
import cookielib

class RequestsCookieJar(cookielib.CookieJar):
    """Compatibility class; is a http.cookiejar.CookieJar, but exposes a dict
    interface.

    This is the CookieJar we create by default for requests and sessions that
    don't specify one, since some clients may expect response.cookies and
    session.cookies to support dict operations.
    """

    def __getitem__(self, key):
        """Get a cookie by key.

        Args:
            key (str): The name of the cookie.

        Returns:
            str: The value of the cookie.

        Raises:
            KeyError: If the cookie does not exist.
        """
        if not isinstance(key, str):
            raise KeyError(key)
        for cookie in self:
            if cookie.name == key:
                return cookie.value
        raise KeyError(key)

    def __setitem__(self, key, value):
        """Set a cookie by key.

        Args:
            key (str): The name of the cookie.
            value (str): The value of the cookie.

        Raises:
            TypeError: If the key is not a string.
        """
        if not isinstance(key, str):
            raise TypeError("Key must be a string")
        self.set(key, value)

    def __delitem__(self, key):
        """Delete a cookie by key.

        Args:
            key (str): The name of the cookie.

        Raises:
            TypeError: If the key is not a string.
            KeyError: If the cookie does not exist.
        """
        if not isinstance(key, str):
            raise TypeError("Key must be a string")
        self.clear(key=key)

    def __iter__(self):
        """Iterate over cookie names."""
        return iter([cookie.name for cookie in self])

    def __len__(self):
        """Return the number of cookies."""
        return len([cookie for cookie in self])

# Example usage
cookie_jar = RequestsCookieJar()
cookie_jar["foo"] = "1"
print(cookie_jar["foo"])  # prints: 1
del cookie_jar["foo"]
try:
    print(cookie_jar["foo"])  # raises KeyError
except KeyError:
    print("KeyError raised")

for key in cookie_jar:
    print(key)

print(len(cookie_jar))  # prints: 0
