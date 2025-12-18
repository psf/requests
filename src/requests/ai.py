"""
requests.ai
~~~~~~~~~~~

This module provides AI capabilities for the Requests library.
"""

import os
import json
import logging

logger = logging.getLogger(__name__)

# Global configuration
api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("REQUESTS_AI_KEY")

def _check_genai():
    """Verify if google-generativeai is installed and configured."""
    try:
        import google.generativeai as genai
        if not api_key:
            raise ValueError("AI API key is not configured. Use requests.ai.configure(key) or set GOOGLE_API_KEY environment variable.")
        genai.configure(api_key=api_key)
        return genai
    except ImportError:
        raise ImportError("google-generativeai is not installed. Run 'pip install google-generativeai'.")

def configure(key):
    """Configure the AI module with an API key."""
    global api_key
    api_key = key

class AIProxy:
    """A proxy object to provide AI features on Response and Session objects."""

    def __init__(self, parent):
        self._parent = parent
        self._model = None

    def _get_model(self):
        genai = _check_genai()
        if self._model is None:
            self._model = genai.GenerativeModel('gemini-1.5-flash')
        return self._model

    def extract(self, prompt, schema=None):
        """Extract structured data from the response content using AI."""
        # Use local import to avoid circular dependency
        from .models import Response
        
        if not isinstance(self._parent, Response):
            raise TypeError("extract() can only be called on a Response object.")

        content = self._parent.text
        full_prompt = f"Extract the following information from this content: {prompt}\n\nContent:\n{content}"
        
        if schema:
            full_prompt += f"\n\nPlease provide the output in the following JSON format: {json.dumps(schema)}"

        model = self._get_model()
        response = model.generate_content(full_prompt)
        
        try:
            text = response.text
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif text.strip().startswith("{"):
                text = text.strip()
            return json.loads(text)
        except (ValueError, json.JSONDecodeError):
            return response.text

    def analyze(self):
        """Analyze the response and provide insights or fix suggestions."""
        from .models import Response

        if not isinstance(self._parent, Response):
            raise TypeError("analyze() can only be called on a Response object.")

        analysis_prompt = (
            f"Analyze this HTTP response and explain it in simple terms. "
            f"If it's an error (status {self._parent.status_code}), suggest possible fixes.\n\n"
            f"URL: {self._parent.url}\n"
            f"Status: {self._parent.status_code}\n"
            f"Headers: {dict(self._parent.headers)}\n"
            f"Body preview: {self._parent.text[:1000]}"
        )

        model = self._get_model()
        response = model.generate_content(analysis_prompt)
        return response.text

    def humanize(self):
        """Adjust session settings to mimic human behavior."""
        from .sessions import Session

        if not isinstance(self._parent, Session):
            raise TypeError("humanize() can only be called on a Session object.")

        humanize_prompt = (
            "Generate a set of HTTP headers for a modern Chrome browser on Windows 11. "
            "Return only a JSON object of headers."
        )

        model = self._get_model()
        response = model.generate_content(humanize_prompt)
        
        try:
            text = response.text
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            headers = json.loads(text)
            self._parent.headers.update(headers)
        except Exception as e:
            logger.warning(f"Failed to humanize session: {e}")
            self._parent.headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
