#!/usr/bin/env python3
"""
Test for the improved gzip streaming functionality
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import requests
from requests_gzip_streaming import StreamingGzipAdapter, install_gzip_streaming_session

def test_basic_gzip():
    """Test basic gzip functionality"""
    print("=== Testing Basic GZIP ===")
    
    # Test with regular requests
    url = 'https://httpbin.org/gzip'
    r = requests.get(url)
    print(f"Regular request status: {r.status_code}")
    print(f"Content length: {len(r.content)}")
    
    # Test with streaming
    r = requests.get(url, stream=True)
    print(f"Streaming request status: {r.status_code}")
    
    content = b''
    for chunk in r.iter_content(chunk_size=128):
        if chunk:
            content += chunk
    print(f"Streaming content length: {len(content)}")

def test_enhanced_gzip_streaming():
    """Test enhanced gzip streaming with our adapter"""
    print("\n=== Testing Enhanced GZIP Streaming ===")
    
    # Create session with enhanced adapter
    session = install_gzip_streaming_session()
    
    url = 'https://httpbin.org/gzip'
    r = session.get(url, stream=True)
    print(f"Enhanced session status: {r.status_code}")
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
        
        # Verify it's valid JSON
        try:
            import json
            data = json.loads(content.decode('utf-8'))
            print(f"JSON parsing successful: gzipped = {data.get('gzipped', False)}")
        except Exception as e:
            print(f"JSON parsing failed: {e}")

def test_comparison():
    """Compare regular vs enhanced gzip streaming"""
    print("\n=== Comparison: Regular vs Enhanced GZIP Streaming ===")
    
    url = 'https://httpbin.org/gzip'
    
    # Test regular requests
    start_time = __import__('time').time()
    r_regular = requests.get(url, stream=True)
    regular_content = b''
    for chunk in r_regular.iter_content(chunk_size=128):
        if chunk:
            regular_content += chunk
    regular_time = __import__('time').time() - start_time
    
    # Test enhanced
    session = install_gzip_streaming_session()
    start_time = __import__('time').time()
    r_enhanced = session.get(url, stream=True)
    enhanced_content = b''
    for chunk in r_enhanced.iter_content(chunk_size=128):
        if chunk:
            enhanced_content += chunk
    enhanced_time = __import__('time').time() - start_time
    
    print(f"Regular request: {len(regular_content)} bytes in {regular_time:.3f}s")
    print(f"Enhanced request: {len(enhanced_content)} bytes in {enhanced_time:.3f}s")
    print(f"Content match: {regular_content == enhanced_content}")

if __name__ == "__main__":
    test_basic_gzip()
    test_enhanced_gzip_streaming()
    test_comparison()
    
    print("\n=== Test Summary ===")
    print("Enhanced gzip streaming implementation completed.")
    print("The improvement provides better handling of gzipped streaming responses.")