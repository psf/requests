import requests
from unittest.mock import MagicMock
import json

# We'll mock the AI model to test the integration without an API key
import requests.ai

# Mock the GenerativeModel
mock_model = MagicMock()
requests.ai.AIProxy._get_model = MagicMock(return_value=mock_model)

def test_extract():
    print("\n--- Testing Response.ai.extract() ---")
    # Mock response from Gemini
    mock_response = MagicMock()
    mock_response.text = '{"name": "Requests", "stars": "50k+"}'
    mock_model.generate_content.return_value = mock_response

    # Create a dummy response object
    r = requests.Response()
    r.status_code = 200
    r._content = b"Requests library has over 50k stars on GitHub."
    r.encoding = 'utf-8'

    result = r.ai.extract("Extract name and stars", schema={"name": "str", "stars": "str"})
    print(f"Extracted: {result}")
    assert result['name'] == "Requests"

def test_analyze():
    print("\n--- Testing Response.ai.analyze() ---")
    mock_response = MagicMock()
    mock_response.text = "This is a 403 Forbidden error. You might need to set a User-Agent header."
    mock_model.generate_content.return_value = mock_response

    r = requests.Response()
    r.status_code = 403
    r.url = "https://example.com/api"
    r.headers = {"Server": "Cloudflare"}
    r._content = b"Forbidden"
    
    analysis = r.ai.analyze()
    print(f"Analysis: {analysis}")
    assert "403 Forbidden" in analysis

def test_humanize():
    print("\n--- Testing Session.ai.humanize() ---")
    mock_response = MagicMock()
    mock_response.text = '{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36", "Accept-Language": "en-US,en;q=0.9"}'
    mock_model.generate_content.return_value = mock_response

    s = requests.Session()
    s.ai.humanize()
    print(f"Humanized Headers: {dict(s.headers)}")
    assert "Chrome/120.0.0.0" in s.headers['User-Agent']

if __name__ == "__main__":
    # Ensure requests.ai is imported and mockable
    try:
        test_extract()
        test_analyze()
        test_humanize()
        print("\nIntegration tests passed!")
    except Exception as e:
        print(f"\nIntegration tests failed: {e}")
        import traceback
        traceback.print_exc()
