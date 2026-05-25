
"""
Tests for requests/validators.py header validation.
"""
import sys
sys.path.insert(0, '.')

from requests.validators import is_valid_header_name, validate_headers, sanitize_headers


def test_valid_header():
    assert is_valid_header_name("Content-Type") == True
    assert is_valid_header_name("X-Custom-Header_123") == True
    print("✅ test_valid_header passed")


def test_invalid_pseudo_header():
    assert is_valid_header_name(":method") == False
    assert is_valid_header_name(":path") == False
    print("✅ test_invalid_pseudo_header passed")


def test_invalid_control_chars():
    assert is_valid_header_name("invalid\nheader") == False
    assert is_valid_header_name("invalid\rheader") == False
    assert is_valid_header_name("invalid\x01header") == False
    print("✅ test_invalid_control_chars passed")


def test_validate_headers():
    try:
        validate_headers({":method": "GET"})
        assert False, "Should raise ValueError"
    except ValueError as e:
        print(f"✅ test_validate_headers caught: {e}")
        
    # Should not raise
    validate_headers({"Content-Type": "text/html"})
    print("✅ test_validate_headers passed for valid headers")


def test_sanitize_headers():
    dirty = {":method": "GET", "Content-Type": "text/html", "valid": "true"}
    clean = sanitize_headers(dirty)
    assert ":method" not in clean
    assert "Content-Type" in clean
    assert "valid" in clean
    print(f"✅ test_sanitize_headers passed: {clean}")


if __name__ == "__main__":
    test_valid_header()
    test_invalid_pseudo_header()
    test_invalid_control_chars()
    test_validate_headers()
    test_sanitize_headers()
    print("\n✅ All validators tests passed!")
