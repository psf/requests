"""
Improved gzip streaming support for requests library

This module provides enhanced handling of gzipped streaming responses,
addressing the issue where streaming gzipped content may not be handled optimally.

Changes:
- Added GzipStreamResponse class for better streaming handling
- Added StreamingGzipAdapter for improved gzip decompression during streaming
- Added utility function to install enhanced streaming globally

Usage:
    from requests_gzip_streaming import install_gzip_streaming_session
    
    # Create session with enhanced gzip streaming
    session = install_gzip_streaming_session()
    
    # Use normally - gzip streaming is handled automatically
    response = session.get('https://example.com/gzip-content', stream=True)
"""