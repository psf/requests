# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives.kdf import KeyDerivationFunction

HKDF = rust_openssl.kdf.HKDF
HKDFExpand = rust_openssl.kdf.HKDFExpand

KeyDerivationFunction.register(HKDF)
KeyDerivationFunction.register(HKDFExpand)

__all__ = ["HKDF", "HKDFExpand"]
