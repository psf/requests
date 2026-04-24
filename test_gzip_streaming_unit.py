import unittest
import gzip
import io
from unittest.mock import Mock, patch
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from requests_gzip_streaming import GzipStreamResponse, StreamingGzipAdapter


class TestGzipStreamResponse(unittest.TestCase):
    """Test cases for GzipStreamResponse"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_response = Mock()
        self.mock_response.headers = {'Content-Encoding': 'gzip'}
        self.mock_response.iter_content.return_value = [
            b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff',
            b'k\xcb\xc8\x50\x02\x04\xb3\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00'
        ]
        
        self.response = GzipStreamResponse(self.mock_response)
    
    def test_gzip_streaming_response_creation(self):
        """Test that GzipStreamResponse is created correctly"""
        self.assertEqual(self.response.original_response, self.mock_response)
        self.assertEqual(self.response.headers['Content-Encoding'], 'gzip')
    
    def test_iter_content_with_gzip(self):
        """Test iter_content with gzipped content"""
        chunks = list(self.response.iter_content(chunk_size=10))
        self.assertGreater(len(chunks), 0)
        self.assertTrue(all(isinstance(chunk, bytes) for chunk in chunks))
    
    def test_iter_content_without_gzip(self):
        """Test iter_content without gzipped content"""
        self.response.headers = {'Content-Encoding': ''}
        chunks = list(self.response.iter_content(chunk_size=10))
        self.assertEqual(len(chunks), 0)  # Should yield nothing for non-gzip


class TestStreamingGzipAdapter(unittest.TestCase):
    """Test cases for StreamingGzipAdapter"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.adapter = StreamingGzipAdapter()
    
    def test_adapter_creation(self):
        """Test that StreamingGzipAdapter is created correctly"""
        self.assertIsInstance(self.adapter, StreamingGzipAdapter)
        self.assertIsInstance(self.adapter, HTTPAdapter)
    
    @patch('requests_gzip_streaming.HTTPAdapter.build_response')
    def test_build_response_with_gzip(self, mock_build_response):
        """Test build_response with gzipped content"""
        mock_request = Mock()
        mock_response = Mock()
        mock_response.headers = {'Content-Encoding': 'gzip'}
        mock_response.raw = Mock()
        mock_response.raw.stream = True
        
        mock_build_response.return_value = Mock(
            headers={'Content-Encoding': 'gzip'},
            raw=Mock()
        )
        
        result = self.adapter.build_response(mock_request, mock_response)
        # The result should be enhanced for gzip content
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()