"""
requests.structures
~~~~~~~~~~~~~~~~~~~

Data structures that power Requests.
"""

from collections import OrderedDict

from .compat import Mapping, MutableMapping


class CaseInsensitiveDict(MutableMapping):
    """
    A case-insensitive dictionary-like container optimized for handling HTTP headers and other case-insensitive key-value pairs, providing seamless access and storage while preserving the original key casing for retrieval.
    
        Implements all methods and operations of
        ``MutableMapping`` as well as dict's ``copy``. Also
        provides ``lower_items``.
    
        All keys are expected to be strings. The structure remembers the
        case of the last key to be set, and ``iter(instance)``,
        ``keys()``, ``items()``, ``iterkeys()``, and ``iteritems()``
        will contain case-sensitive keys. However, querying and contains
        testing is case insensitive::
    
            cid = CaseInsensitiveDict()
            cid['Accept'] = 'application/json'
            cid['aCCEPT'] == 'application/json'  # True
            list(cid) == ['Accept']  # True
    
        For example, ``headers['content-encoding']`` will return the
        value of a ``'Content-Encoding'`` response header, regardless
        of how the header name was originally stored.
    
        If the constructor, ``.update``, or equality comparison
        operations are given keys that have equal ``.lower()``s, the
        behavior is undefined.
    """


    def __init__(self, data=None, **kwargs):
        """
        Initialize the instance with optional data and additional keyword arguments to support flexible configuration.
        
        Args:
            data: Initial data to populate the instance, allowing users to set default values or state at creation time
            **kwargs: Additional configuration options passed to the update method, enabling seamless integration with request parameters or session settings
        """
        self._store = OrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key, value):
        """
        Stores a key-value pair in the internal store using the lowercase version of the key for case-insensitive lookup, enabling consistent retrieval regardless of how the key was originally provided.
        
        Args:
            key: The key to set, used for retrieval via its lowercase form to support case-insensitive access
            value: The value associated with the key
        """
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key):
        """
        Returns the value associated with the given key, using lowercase for case-insensitive lookup.
        
        This enables consistent retrieval of headers or other case-sensitive data in HTTP requests, where header names are typically treated as case-insensitive by the HTTP specification. The lowercase conversion ensures reliable access regardless of how the key was originally provided.
        
        Args:
            key: The key to retrieve the value for. The key is converted to lowercase before lookup.
        
        Returns:
            The value associated with the lowercase version of the key from the internal store.
        """
        return self._store[key.lower()][1]

    def __delitem__(self, key):
        """
        Remove an item from the underlying store using the lowercase version of the key.
        
        This ensures consistent key lookup and removal across case-insensitive operations, which is essential for maintaining reliable session state and cookie management in HTTP requests. The lowercase conversion aligns with standard HTTP header and cookie handling practices, where case insensitivity is expected.
        
        Args:
            key: The key to remove, converted to lowercase before lookup
        """
        del self._store[key.lower()]

    def __iter__(self):
        """
        Iterates over the cased keys from stored (casedkey, mappedvalue) pairs, enabling convenient access to original key names while preserving case sensitivity.
        
        This supports consistent key retrieval in case-sensitive contexts, which is essential for accurate header or parameter handling in HTTP requests, aligning with Requests' goal of providing reliable and predictable HTTP interaction.
        """
        return (casedkey for casedkey, mappedvalue in self._store.values())

    def __len__(self):
        """
        Returns the number of items stored in the internal storage container, enabling efficient tracking of cached responses and session data.
        
        Returns:
            Integer representing the count of items in the underlying store
        """
        return len(self._store)

    def lower_items(self):
        """
        Returns an iterator over the dictionary's items with lowercase keys, ensuring consistent key access regardless of original case.
        
        This is particularly useful in Requests for handling HTTP headers and other case-insensitive data structures, where uniformity across different input formats is essential for reliable behavior.
        
        Returns:
            An iterator of (lowercase_key, value) pairs from the internal store.
        """
        return ((lowerkey, keyval[1]) for (lowerkey, keyval) in self._store.items())

    def __eq__(self, other):
        """
        Compare this CaseInsensitiveDict with another mapping for equality, ignoring case differences in keys.
        
        This comparison is essential for HTTP header handling, where header names are case-insensitive by specification. By comparing keys without regard to case, Requests ensures consistent and correct behavior when validating or matching headers across different request and response objects.
        
        Args:
            other: Another mapping to compare against. If not a Mapping, returns NotImplemented.
        
        Returns:
            True if both dictionaries have the same key-value pairs when keys are compared case-insensitively, False otherwise.
        """
        if isinstance(other, Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    # Copy is required
    def copy(self):
        """
        Returns a shallow copy of the case-insensitive dictionary, preserving the ability to access keys regardless of case. This is particularly useful in HTTP headers and other scenarios where case-insensitive key lookup is required, aligning with the Requests library's goal of simplifying HTTP interactions by abstracting away common complexities like header case variations.
        
        Returns:
            A new CaseInsensitiveDict containing the same values as the original.
        """
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self):
        """
        Returns a string representation of the dictionary contents, useful for debugging and inspecting request data structures.
        
        This method supports the library's goal of providing intuitive, developer-friendly HTTP interactions by enabling clear visualization of internal state—such as headers, cookies, or form data—in a format that matches Python's dict literal syntax. This aids in troubleshooting and ensures consistency with Python's expected behavior for object representation.
        
        Returns:
            A string representation of the dictionary, formatted as a Python dict literal.
        """
        return str(dict(self.items()))


class LookupDict(dict):
    """
    Dictionary lookup object.
    """


    def __init__(self, name=None):
        """
        Initializes a new instance with an optional name to support identifiable HTTP sessions within the Requests library.
        
        Args:
            name: The name to assign to the instance, useful for tracking or debugging specific sessions (default: None)
        """
        self.name = name
        super().__init__()

    def __repr__(self):
        """
        Returns a concise, readable representation of the lookup object for debugging and logging purposes, formatted as '<lookup name>' where 'name' is the lookup's identifier. This helps developers quickly identify lookup instances during development or when inspecting request components in the Requests library.
        
        Returns:
            A formatted string in the form '<lookup name>', where 'name' is the lookup's name attribute.
        """
        return f"<lookup '{self.name}'>"

    def __getitem__(self, key):
        """
        Retrieves the value associated with the given key from the object's internal state, returning None if the key is not present.
        
        This method supports flexible access to stored attributes or configuration values within Requests objects, such as session data or request metadata, enabling convenient lookup without raising KeyError. It aligns with Python's dictionary-like interface, making it intuitive for users to access internal state while maintaining safety through default fallbacks.
        
        Args:
            key: The key to look up in the object's internal dictionary
        
        Returns:
            The value for the key if present, otherwise None
        """
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    def get(self, key, default=None):
        """
        Returns the value for a given key from the object's internal dictionary, allowing safe access to stored attributes without raising KeyError.
        
        Args:
            key: The attribute name to retrieve from the object's internal state
            default: Value to return if the key is not found (default: None)
        
        Returns:
            The value associated with the key, or the default value if the key is not present
        
        This method supports safe attribute access in Requests objects, enabling consistent and reliable retrieval of internal state data—such as request configurations or session settings—without requiring explicit error handling. It aligns with Requests' goal of simplifying HTTP interactions by providing intuitive, predictable behavior even when dealing with optional or dynamic properties.
        """
        return self.__dict__.get(key, default)
