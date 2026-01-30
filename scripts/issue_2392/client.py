#!/usr/bin/env python
"""
Reproduction client for issue #2392.

Calls requests.get() with a short timeout and accesses r.content.
With a chunked response that is slow (server delays between chunks), the read
times out during streaming.

Expected (after fix): requests.exceptions.ReadTimeout
Before fix: requests.exceptions.ConnectionError with "Read timed out" message.

Usage:
    Start server.py first, then:
    python client.py
"""
import os
import sys

# Ensure in-tree requests is used (works from repo root or scripts/issue_2392)
_script_dir = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.abspath(os.path.join(_script_dir, "..", ".."))
sys.path.insert(0, os.path.join(_repo_root, "src"))

import requests
from requests.exceptions import ReadTimeout, ConnectionError as RequestsConnectionError


def main():
    url = "http://127.0.0.1:8000/"
    timeout = 0.5

    try:
        r = requests.get(url, timeout=timeout)
        # Accessing .content triggers iter_content(); timeout occurs while
        # waiting for the next chunk (server delays 2s, client timeout 0.5s)
        _ = r.content
        print("Unexpected: no exception raised")
        return 1
    except ReadTimeout as e:
        print("OK: requests.exceptions.ReadTimeout raised (fix verified)")
        print(f"  {e}")
        return 0
    except RequestsConnectionError as e:
        if "Read timed out" in str(e) or "timed out" in str(e).lower():
            print("FAIL: ConnectionError raised instead of ReadTimeout (issue #2392)")
            print(f"  {e}")
            return 1
        raise

    return 0


if __name__ == "__main__":
    sys.exit(main())
