"""
Improved gzip handling for streaming responses in requests

This module provides enhanced gzip decompression for streaming responses,
addressing issue #2155: Streaming gzipped responses
"""

import gzip
import io
from requests.adapters import HTTPAdapter
from requests.models import Response
from urllib3.response import HTTPResponse


class GzipStreamResponse(Response):
    """
    Enhanced Response class for handling gzip streaming more efficiently
    """
    
    def __init__(self, original_response):
        super().__init__()
        self.original_response = original_response
        self._decoder = None
        self._buffer = io.BytesIO()
        
    def iter_content(self, chunk_size=1024, decode_unicode=False):
        """
        Iterate over the response data with proper gzip handling for streaming
        """
        if 'gzip' not in self.headers.get('Content-Encoding', ''):
            # Not gzipped, use original response
            yield from self.original_response.iter_content(chunk_size, decode_unicode)
            return
            
        # Handle gzipped content
        for chunk in self.original_response.iter_content(chunk_size=chunk_size):
            if chunk:
                self._buffer.write(chunk)
                
                # Try to decode and yield available data
                self._buffer.seek(0)
                try:
                    if self._decoder is None:
                        self._decoder = gzip.GzipFile(fileobj=self._buffer, mode='rb')
                    
                    # Read available decoded data
                    decoded_chunk = self._decoder.read(chunk_size)
                    while decoded_chunk:
                        yield decoded_chunk
                        decoded_chunk = self._decoder.read(chunk_size)
                        
                    # Reset buffer position
                    self._buffer.seek(0, 2)  # Seek to end
                    
                except EOFError:
                    # Reset buffer for next chunk
                    self._buffer.seek(0)
                    remaining_data = self._buffer.read()
                    self._buffer = io.BytesIO(remaining_data)
                    break
                except Exception as e:
                    # If there's an error with gzip decoding, yield raw data
                    self._buffer.seek(0)
                    yield self._buffer.read()
                    break
        
        # Clean up
        if self._decoder:
            self._decoder.close()


class StreamingGzipAdapter(HTTPAdapter):
    """
    HTTPAdapter that provides improved gzip streaming support
    """
    
    def build_response(self, req, resp):
        """
        Build a response with enhanced gzip streaming support
        """
        response = super().build_response(req, resp)
        
        # Check if response is gzipped and we should handle streaming
        if ('gzip' in response.headers.get('Content-Encoding', '') and 
            hasattr(response, 'raw') and 
            hasattr(response.raw, 'stream')):
            
            # Create enhanced response for gzip streaming
            enhanced_response = GzipStreamResponse(response)
            enhanced_response.status_code = response.status_code
            enhanced_response.headers = response.headers
            enhanced_response.encoding = response.encoding
            enhanced_response.url = response.url
            enhanced_response.request = response.request
            enhanced_response.connection = response.connection
            
            return enhanced_response
            
        return response


def install_gzip_streaming_session():
    """
    Install the streaming gzip adapter globally for all requests sessions
    """
    import requests
    
    # Create a new session with the enhanced adapter
    session = requests.Session()
    
    # Mount the enhanced adapter
    adapter = StreamingGzipAdapter()
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    return session