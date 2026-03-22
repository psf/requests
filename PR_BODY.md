## Summary
Fix `HTTPDigestAuth` so UTF-8 byte credentials are handled as text instead of being stringified as Python byte reprs.

## Root Cause
`HTTPDigestAuth.build_digest_header` interpolated `self.username` and `self.password` directly into f-strings. When bytes were provided, Python converted them to repr-like strings (for example `b'Ond\\xc5\\x99ej'`), producing an incorrect digest username and digest input.

## Changes Made
- Normalize byte `username` and `password` to native strings using UTF-8 decoding inside `HTTPDigestAuth.build_digest_header`.
- Use normalized values for digest input (`A1`) and the emitted `Digest username="..."` field.
- Added a regression test covering UTF-8 byte credentials for digest auth header construction.

## Verification
- Ran `pytest -q tests/test_requests.py -k "digest_auth_header_handles_utf8_byte_credentials or basic_auth_str_is_always_native"`.
- Result: `3 passed, 330 deselected`.
- Attempted low-level digest socket tests, but sandbox restrictions prevented local socket bind/connect.

## Notes
- The fix is intentionally minimal and scoped to digest credential normalization for byte inputs.
