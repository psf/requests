#!/usr/bin/env python3
"""
Test script to verify gzip streaming behavior in requests
Issue #2155: Streaming gzipped responses
"""

import requests
import gzip
import io
import time
from threading import Thread

def test_gzip_streaming_current():
    """Test current gzip streaming behavior"""
    print("=== Testing Current GZIP Streaming Behavior ===")
    
    # Test 1: Regular gzip response
    url = 'https://httpbin.org/gzip'
    print(f"Testing URL: {url}")
    
    # Test with stream=True
    r = requests.get(url, stream=True)
    print(f"Status code: {r.status_code}")
    print(f"Content-Encoding: {r.headers.get('Content-Encoding')}")
    
    if r.status_code == 200:
        content = b''
        chunk_count = 0
        
        for chunk in r.iter_content(chunk_size=128):
            if chunk:
                chunk_count += 1
                content += chunk
                print(f"Chunk {chunk_count}: {len(chunk)} bytes")
        
        print(f"Total chunks: {chunk_count}")
        print(f"Total content length: {len(content)} bytes")
        print(f"Content preview: {content[:100]}")
        
        # Verify it's valid JSON
        try:
            import json
            data = json.loads(content.decode('utf-8'))
            print(f"JSON parsing successful: {data.get('gzipped', False)}")
        except Exception as e:
            print(f"JSON parsing failed: {e}")
    else:
        print(f"Failed to get response: {r.status_code}")

def test_gzip_streaming_large():
    """Test gzip streaming with larger content"""
    print("\n=== Testing Large GZIP Streaming ===")
    
    # Create a test server that serves gzipped content
    # For now, we'll use a different approach
    url = 'https://httpbin.org/stream/5'
    r = requests.get(url, stream=True)
    
    print(f"Status code: {r.status_code}")
    print(f"Content-Encoding: {r.headers.get('Content-Encoding')}")
    
    if r.status_code == 200:
        chunk_count = 0
        total_size = 0
        
        for chunk in r.iter_content(chunk_size=256):
            if chunk:
                chunk_count += 1
                total_size += len(chunk)
                print(f"Chunk {chunk_count}: {len(chunk)} bytes")
        
        print(f"Total chunks: {chunk_count}")
        print(f"Total size: {total_size} bytes")

def test_gzip_chunked_encoding():
    """Test gzip with chunked encoding"""
    print("\n=== Testing GZIP with Chunked Encoding ===")
    
    # This test would require a server that sends gzipped content in chunks
    # For now, we'll test the basic functionality
    url = 'https://httpbin.org/gzip'
    r = requests.get(url, stream=True)
    
    print(f"Status code: {r.status_code}")
    print(f"Transfer-Encoding: {r.headers.get('Transfer-Encoding')}")
    print(f"Content-Encoding: {r.headers.get('Content-Encoding')}")
    
    # Test reading in different chunk sizes
    for chunk_size in [64, 128, 256, 512]:
        print(f"\n--- Testing with chunk_size={chunk_size} ---")
        r = requests.get(url, stream=True)
        
        content = b''
        chunk_count = 0
        
        for chunk in r.iter_content(chunk_size=chunk_size):
            if chunk:
                chunk_count += 1
                content += chunk
        
        print(f"Chunks received: {chunk_count}")
        print(f"Total content: {len(content)} bytes")

if __name__ == "__main__":
    test_gzip_streaming_current()
    test_gzip_streaming_large()
    test_gzip_chunked_encoding()
    
    print("\n=== Summary ===")
    print("Current requests library appears to handle gzip streaming correctly.")
    print("Further investigation needed to understand the specific issue #2155.")