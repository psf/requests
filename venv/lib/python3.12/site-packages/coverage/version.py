# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/nedbat/coveragepy/blob/master/NOTICE.txt

"""The version and URL for coverage.py"""
# This file is exec'ed in setup.py, don't import anything!

from __future__ import annotations

# version_info: same semantics as sys.version_info.
# _dev: the .devN suffix if any.
version_info = (7, 11, 0, "final", 0)
_dev = 0


def _make_version(
    major: int,
    minor: int,
    micro: int,
    releaselevel: str = "final",
    serial: int = 0,
    dev: int = 0,
) -> str:
    """Create a readable version string from version_info tuple components."""
    assert releaselevel in ["alpha", "beta", "candidate", "final"]
    version = f"{major}.{minor}.{micro}"
    if releaselevel != "final":
        short = {"alpha": "a", "beta": "b", "candidate": "rc"}[releaselevel]
        version += f"{short}{serial}"
    if dev != 0:
        version += f".dev{dev}"
    return version


__version__ = _make_version(*version_info, _dev)
__url__ = f"https://coverage.readthedocs.io/en/{__version__}"
