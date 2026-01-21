#!/bin/bash
set -euo pipefail

# CI runners may inject proxy/CA env vars; make tests deterministic.
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
unset REQUESTS_CA_BUNDLE CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR
export NO_PROXY="127.0.0.1,localhost"
export no_proxy="127.0.0.1,localhost"

case "${1:-}" in
  base)
    python -m pytest -q \
      tests/test_structures.py \
      tests/test_utils.py \
      tests/test_hooks.py \
      tests/test_status_codes.py
    ;;
  new)
    python -m pytest -q tests/test_max_response_size.py
    ;;
  *)
    echo "Usage: ./test.sh {base|new}"
    exit 1
    ;;
esac
