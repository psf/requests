# Reproduction for issue #2392: chunked response timeout

When a response is chunked and a read timeout occurs during streaming, Requests should raise `requests.exceptions.ReadTimeout`, not `requests.exceptions.ConnectionError`.

## Manual reproduction

1. **Start the server** (in one terminal):

   ```bash
   cd scripts/issue_2392
   python server.py
   ```

2. **Run the client** (in another terminal, from repo root so `src` is on path):

   ```bash
   cd /path/to/requests
   python scripts/issue_2392/client.py
   ```

With the fix, the client prints: `OK: requests.exceptions.ReadTimeout raised (fix verified)` and exits 0.

Without the fix, the client would raise `requests.exceptions.ConnectionError: ... Read timed out` and report failure.
