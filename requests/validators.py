"""
Header validation utilities for requests.

This module provides functions to validate HTTP headers according to RFC 7230
and reject potentially dangerous or malformed headers.
"""

from typing import Dict, Any


# RFC 7230: field-name must not start with ':' (pseudo-headers from HTTP/2)
# Also disallow control characters in header names
def is_valid_header_name(name: str) -> bool:
    """
    Check if a header name is valid according to RFC 7230.
    
    Args:
        name: The header name to validate
        
    Returns:
        True if valid, False otherwise
        
    Examples:
        >>> is_valid_header_name("Content-Type")
        True
        >>> is_valid_header_name(":method")
        False
        >>> is_valid_header_name("invalid\nheader")
        False
    """
    if not name:
        return False
    
    # Check for pseudo-headers (HTTP/2 style like ':method', ':path')
    if name.startswith(':'):
        return False
    
    # Check for control characters (ASCII 0-31 except HTAB (9))
    for char in name:
        code = ord(char)
        if code < 32 and code != 9:  # Allow HTAB (9)
            return False
            
    # Check for ':' in name (not allowed in field-name per RFC 7230)
    if ':' in name:
        return False
        
    return True


def validate_headers(headers: Dict[str, Any]) -> None:
    """
    Validate a dictionary of headers.
    
    Args:
        headers: Dictionary of headers to validate
        
    Raises:
        ValueError: If any header name is invalid
    """
    for key in headers:
        if not is_valid_header_name(key):
            raise ValueError(
                f"Invalid header name: {key!r}. "
                "Header names must not start with ':' and must not contain control characters."
            )


def sanitize_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove invalid headers from a dictionary.
    
    Args:
        headers: Dictionary of headers to sanitize
        
    Returns:
        New dictionary with only valid headers
    """
    return {k: v for k, v in headers.items() if is_valid_header_name(k)}


if __name__ == "__main__":
    # Quick tests
    assert is_valid_header_name("Content-Type") == True
    assert is_valid_header_name(":method") == False
    assert is_valid_header_name("invalid\nheader") == False
    assert is_valid_header_name("") == False
    assert is_valid_header_name("valid-header_123") == True
    
    # Test validate_headers
    try:
        validate_headers({":method": "GET"})
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"✅ Correctly caught invalid header: {e}")
        
    # Test sanitize_headers
    dirty = {":method": "GET", "Content-Type": "text/html", "valid": "true"}
    clean = sanitize_headers(dirty)
    assert ":method" not in clean
    assert "Content-Type" in clean
    assert "valid" in clean
    print(f"✅ Sanitization works: {clean}")
    
    print("\n✅ All validation tests passed!")