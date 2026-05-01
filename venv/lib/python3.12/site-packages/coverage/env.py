# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/nedbat/coveragepy/blob/master/NOTICE.txt

"""Determine facts about the environment."""

from __future__ import annotations

import os
import platform
import sys
from collections.abc import Iterable
from typing import Any, Final

# debug_info() at the bottom wants to show all the globals, but not imports.
# Grab the global names here to know which names to not show. Nothing defined
# above this line will be in the output.
_UNINTERESTING_GLOBALS = list(globals())
# These names also shouldn't be shown.
_UNINTERESTING_GLOBALS += ["PYBEHAVIOR", "debug_info"]

# Operating systems.
WINDOWS = sys.platform == "win32"
LINUX = sys.platform.startswith("linux")
MACOS = sys.platform == "darwin"

# Python implementations.
CPYTHON = (platform.python_implementation() == "CPython")  # fmt: skip
PYPY = (platform.python_implementation() == "PyPy")  # fmt: skip

# Python versions. We amend version_info with one more value, a zero if an
# official version, or 1 if built from source beyond an official version.
# Only use sys.version_info directly where tools like mypy need it to understand
# version-specfic code, otherwise use PYVERSION.
PYVERSION = sys.version_info + (int(platform.python_version()[-1] == "+"),)

if PYPY:
    # Minimum now is 7.3.16
    PYPYVERSION = tuple(sys.pypy_version_info)  # type: ignore[attr-defined]
else:
    PYPYVERSION = (0,)

# Do we have a GIL?
GIL = getattr(sys, "_is_gil_enabled", lambda: True)()

# Do we ship compiled coveragepy wheels for this version?
SHIPPING_WHEELS = CPYTHON and PYVERSION[:2] <= (3, 14)

# Should we default to sys.monitoring?
SYSMON_DEFAULT = CPYTHON and PYVERSION >= (3, 14)


# Python behavior.
class PYBEHAVIOR:
    """Flags indicating this Python's behavior."""

    # When leaving a with-block, do we visit the with-line exactly,
    # or the context managers in inner-out order?
    #
    # mwith.py:
    #    with (
    #        open("/tmp/one", "w") as f2,
    #        open("/tmp/two", "w") as f3,
    #        open("/tmp/three", "w") as f4,
    #    ):
    #        print("hello 6")
    #
    # % python3.11 -m trace -t mwith.py | grep mwith
    #  --- modulename: mwith, funcname: <module>
    # mwith.py(2):     open("/tmp/one", "w") as f2,
    # mwith.py(1): with (
    # mwith.py(2):     open("/tmp/one", "w") as f2,
    # mwith.py(3):     open("/tmp/two", "w") as f3,
    # mwith.py(1): with (
    # mwith.py(3):     open("/tmp/two", "w") as f3,
    # mwith.py(4):     open("/tmp/three", "w") as f4,
    # mwith.py(1): with (
    # mwith.py(4):     open("/tmp/three", "w") as f4,
    # mwith.py(6):     print("hello 6")
    # mwith.py(1): with (
    #
    # % python3.12 -m trace -t mwith.py | grep mwith
    #  --- modulename: mwith, funcname: <module>
    # mwith.py(2):      open("/tmp/one", "w") as f2,
    # mwith.py(3):      open("/tmp/two", "w") as f3,
    # mwith.py(4):      open("/tmp/three", "w") as f4,
    # mwith.py(6):      print("hello 6")
    # mwith.py(4):      open("/tmp/three", "w") as f4,
    # mwith.py(3):      open("/tmp/two", "w") as f3,
    # mwith.py(2):      open("/tmp/one", "w") as f2,

    exit_with_through_ctxmgr = (PYVERSION >= (3, 12, 6))  # fmt: skip

    # f-strings are parsed as code, pep 701
    fstring_syntax = (PYVERSION >= (3, 12))  # fmt: skip

    # PEP669 Low Impact Monitoring: https://peps.python.org/pep-0669/
    pep669: Final[bool] = bool(getattr(sys, "monitoring", None))

    # Where does frame.f_lasti point when yielding from a generator?
    # It used to point at the YIELD, in 3.13 it points at the RESUME,
    # then it went back to the YIELD.
    # https://github.com/python/cpython/issues/113728
    lasti_is_yield = (PYVERSION[:2] != (3, 13))  # fmt: skip

    # PEP649 and PEP749: Deferred annotations
    deferred_annotations = (PYVERSION >= (3, 14))  # fmt: skip

    # Does sys.monitoring support BRANCH_RIGHT and BRANCH_LEFT?  The names
    # were added in early 3.14 alphas, but didn't work entirely correctly until
    # after 3.14.0a5.
    branch_right_left = pep669 and (PYVERSION > (3, 14, 0, "alpha", 5, 0))


# Coverage.py specifics, about testing scenarios. See tests/testenv.py also.

# Are we coverage-measuring ourselves?
METACOV = os.getenv("COVERAGE_COVERAGE") is not None

# Are we running our test suite?
# Even when running tests, you can use COVERAGE_TESTING=0 to disable the
# test-specific behavior like AST checking.
TESTING = os.getenv("COVERAGE_TESTING") == "True"


def debug_info() -> Iterable[tuple[str, Any]]:
    """Return a list of (name, value) pairs for printing debug information."""
    info = [
        (name, value)
        for name, value in globals().items()
        if not name.startswith("_") and name not in _UNINTERESTING_GLOBALS
    ]
    info += [
        (name, value) for name, value in PYBEHAVIOR.__dict__.items() if not name.startswith("_")
    ]
    return sorted(info)
