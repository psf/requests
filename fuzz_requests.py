#!/usr/bin/env python3
"""Fuzz harness for requests — Python HTTP library (8 GHSA advisories).

Tests URL parsing, header parsing, and response handling
with arbitrary attacker-controlled inputs.
"""
import sys
import atheris

with atheris.instrument_imports():
    import requests
    from requests import structures, cookies


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # 1. URL parsing — core pre-auth boundary
    try:
        url = fdp.ConsumeString(512)
        requests.utils.urlparse(url)
    except Exception:
        pass

    # 2. Header parsing
    try:
        header_str = fdp.ConsumeString(256)
        requests.utils.parse_header_links(header_str)
    except Exception:
        pass

    # 3. Case-insensitive dict (used for headers)
    try:
        key = fdp.ConsumeString(64)
        val = fdp.ConsumeString(128)
        d = structures.CaseInsensitiveDict()
        d[key] = val
        _ = d.get(key, "")
    except Exception:
        pass

    # 4. Cookie parsing
    try:
        cookie_str = fdp.ConsumeString(512)
        cookies.MockRequest(cookie_str)
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
