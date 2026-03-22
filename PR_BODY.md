## Summary
Removed the legacy `ISO-8859-1` default charset fallback for `text/*` responses when no charset is provided.

## Root Cause
`get_encoding_from_headers` still implemented an RFC 2616-era fallback that forced `text/*` content to `ISO-8859-1`, even though that default was removed by newer HTTP specifications.

## Changes Made
- Removed the `text/* -> ISO-8859-1` fallback branch in `src/requests/utils.py:get_encoding_from_headers`.
- Updated `tests/test_utils.py` expectations so `text/plain` without `charset` now returns `None` and added explicit coverage for `application/json` without `charset` still returning `utf-8`.
- Updated wording in `src/requests/models.py` and `docs/user/advanced.rst` to remove references to RFC 2616 default-charset behavior.

## Verification
- `PYTHONPATH=src pytest -q tests/test_utils.py -k get_encoding_from_headers`
- `PYTHONPATH=src pytest -q tests/test_requests.py -k "response_reason_unicode_fallback or response_reason_unicode"`

## Notes
- This is a behavior change for responses with `Content-Type: text/*` and no charset parameter: encoding is now left unset (`None`) and downstream decoding falls back to charset detection.
