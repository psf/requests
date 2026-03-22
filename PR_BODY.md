## Summary
Enabled automatic content decoding on `Response.raw` so streamed gzip-compressed responses can be consumed through file-like readers.

## Root Cause
Requests built responses with `raw.decode_content` disabled, so consumers reading from `response.raw` received compressed bytes by default.

## Changes Made
- Set `response.raw.decode_content = True` in `HTTPAdapter.build_response`.
- Added a regression test in `tests/test_adapters.py` verifying that `build_response` enables decoded raw reads by default.

## Verification
- Ran `PYTHONPATH=src python3 -m pytest -q tests/test_adapters.py tests/test_requests.py -k "decompress_gzip or redirect_with_wrong_gzipped_header"`.
- Result: `2 passed, 332 deselected`.

## Notes
- Callers that need wire-level compressed bytes can still pass `decode_content=False` when reading from `response.raw`.
