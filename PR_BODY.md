## Summary
Reordered proxy merging in session environment handling so explicit Requests proxy configuration is not overridden by environment proxies.

## Root Cause
`Session.merge_environment_settings` added environment proxies before combining with `Session.proxies`, which made environment values win over session-level proxy configuration.

## Changes Made
- Updated `Session.merge_environment_settings` in `src/requests/sessions.py` to merge request/session settings first, then only fill missing proxy values from environment variables.
- Added regression test `test_proxy_env_vars_dont_override_session_proxies` in `tests/test_requests.py`.

## Verification
- Ran: `pytest -q tests/test_requests.py -k "proxy_env_vars_override_default or proxy_env_vars_dont_override_session_proxies"`
- Result: `5 passed, 328 deselected`

## Notes
- This is a minimal precedence fix: explicit request proxies remain highest precedence, `Session.proxies` now correctly overrides env proxies, and env proxies still apply as fallback.
