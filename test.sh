#!/usr/bin/env bash
set -e
case "$1" in
  base)
    pytest -q tests || exit 1
    ;;
  new)
    pytest -q tests/test_ipv6_zone_identifier.py || exit 1
    ;;
  *)
    echo "Usage: ./test.sh {base|new}"
    exit 1
    ;;
esac
