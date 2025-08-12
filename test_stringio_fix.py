#!/usr/bin/env python3
"""
Test script to verify the StringIO Content-Length fix for issue #6917.
This reproduces the original issue and verifies our fix works correctly.
"""

import io
import requests
from requests.utils import super_len
from requests.models import PreparedRequest


def test_stringio_multibyte_characters():
    """Test that StringIO with multi-byte UTF-8 characters has correct Content-Length."""
    print("Testing StringIO with multi-byte UTF-8 characters...")
    
    # Test case 1: Single multi-byte character (💩 = 4 bytes in UTF-8)
    body = io.StringIO("💩")
    length = super_len(body)
    print(f"StringIO('💩') - super_len: {length}, expected: 4")
    assert length == 4, f"Expected 4 bytes, got {length}"
    
    # Test case 2: Multiple multi-byte characters
    body = io.StringIO("💩🚀🎉")  # Each is 4 bytes = 12 total
    length = super_len(body)
    print(f"StringIO('💩🚀🎉') - super_len: {length}, expected: 12")
    assert length == 12, f"Expected 12 bytes, got {length}"
    
    # Test case 3: Mixed ASCII and multi-byte
    body = io.StringIO("Hello💩World")  # Hello(5) + 💩(4) + World(5) = 14
    length = super_len(body)
    print(f"StringIO('Hello💩World') - super_len: {length}, expected: 14")
    assert length == 14, f"Expected 14 bytes, got {length}"
    
    # Test case 4: Only ASCII characters (should work as before)
    body = io.StringIO("Hello")
    length = super_len(body)
    print(f"StringIO('Hello') - super_len: {length}, expected: 5")
    assert length == 5, f"Expected 5 bytes, got {length}"
    
    print("✓ All StringIO super_len tests passed!")


def test_stringio_position_preservation():
    """Test that StringIO position is preserved after super_len call."""
    print("\nTesting StringIO position preservation...")
    
    body = io.StringIO("Hello💩World")
    
    # Move to position 3
    body.seek(3)
    original_pos = body.tell()
    print(f"Original position: {original_pos}")
    
    # Call super_len
    length = super_len(body)
    
    # Check position is preserved
    final_pos = body.tell()
    print(f"Position after super_len: {final_pos}")
    assert final_pos == original_pos, f"Position changed from {original_pos} to {final_pos}"
    
    # Verify we can still read from the correct position
    remaining = body.read()
    print(f"Remaining content from position {original_pos}: '{remaining}'")
    expected_remaining = "lo💩World"
    assert remaining == expected_remaining, f"Expected '{expected_remaining}', got '{remaining}'"
    
    print("✓ StringIO position preservation test passed!")


def test_stringio_partial_read():
    """Test super_len with StringIO that has been partially read."""
    print("\nTesting StringIO with partial read...")
    
    body = io.StringIO("Hello💩World")
    
    # Read first 3 characters
    body.read(3)  # Reads "Hel"
    current_pos = body.tell()
    print(f"After reading 3 chars, position: {current_pos}")
    
    # Get remaining length
    remaining_length = super_len(body)
    
    # Calculate expected: "lo💩World" = lo(2) + 💩(4) + World(5) = 11 bytes
    expected_remaining = len("lo💩World".encode("utf-8"))
    print(f"Remaining length: {remaining_length}, expected: {expected_remaining}")
    assert remaining_length == expected_remaining, f"Expected {expected_remaining}, got {remaining_length}"
    
    print("✓ StringIO partial read test passed!")


def test_prepared_request_content_length():
    """Test that PreparedRequest sets correct Content-Length header."""
    print("\nTesting PreparedRequest Content-Length header...")
    
    # Create a request with StringIO body containing multi-byte characters
    body = io.StringIO("💩")
    req = requests.Request("POST", "http://example.com", data=body)
    prepared = req.prepare()
    
    content_length = prepared.headers.get("Content-Length")
    print(f"Content-Length header: {content_length}")
    assert content_length == "4", f"Expected Content-Length '4', got '{content_length}'"
    
    print("✓ PreparedRequest Content-Length test passed!")


def test_comparison_with_str_and_bytes():
    """Compare behavior with str and bytes to ensure consistency."""
    print("\nTesting consistency with str and bytes...")
    
    test_string = "💩"
    
    # Test with str
    str_length = super_len(test_string)
    print(f"str('💩') - super_len: {str_length}")
    
    # Test with bytes
    bytes_obj = test_string.encode("utf-8")
    bytes_length = super_len(bytes_obj)
    print(f"bytes('💩'.encode('utf-8')) - super_len: {bytes_length}")
    
    # Test with StringIO
    stringio_obj = io.StringIO(test_string)
    stringio_length = super_len(stringio_obj)
    print(f"StringIO('💩') - super_len: {stringio_length}")
    
    # All should be 4 bytes
    assert str_length == bytes_length == stringio_length == 4, \
        f"Inconsistent lengths: str={str_length}, bytes={bytes_length}, stringio={stringio_length}"
    
    print("✓ Consistency test passed!")


if __name__ == "__main__":
    print("Running StringIO Content-Length fix tests...\n")
    
    try:
        test_stringio_multibyte_characters()
        test_stringio_position_preservation()
        test_stringio_partial_read()
        test_prepared_request_content_length()
        test_comparison_with_str_and_bytes()
        
        print("\n🎉 All tests passed! The StringIO Content-Length fix is working correctly.")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)