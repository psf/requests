## Summary
Enable automatic content decoding on `Response.raw` so streamed gzip-encoded responses can be consumed directly via file-like readers.

## Root Cause
Requests built responses with `raw.decode_content=False`, so consumers reading from `response.raw` got compressed bytes by default. This breaks file-like streaming parsers that call `.read()` and expect decoded content.

## Changes Made
- Set `response.raw.decode_content = True` in `HTTPAdapter.build_response`.
- Added a regression test in `tests/test_adapters.py` to verify `build_response` enables decoded raw reads by default.

## Verification
- Ran: `PYTHONPATH=src pytest -q tests/test_adapters.py`
- Result: `2 passed`

## Notes
- Explicit reads that need wire-level compressed bytes can still request `decode_content=False` on read/stream calls.
