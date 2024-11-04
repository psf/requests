# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/nedbat/coveragepy/blob/master/NOTICE.txt

"""Management of core choices."""

from __future__ import annotations

import os
import sys
from typing import Any

from coverage import env
from coverage.disposition import FileDisposition
from coverage.exceptions import ConfigError
from coverage.pytracer import PyTracer
from coverage.sysmon import SysMonitor
from coverage.types import (
    TFileDisposition,
    Tracer,
    TWarnFn,
)


try:
    # Use the C extension code when we can, for speed.
    from coverage.tracer import CTracer, CFileDisposition
    HAS_CTRACER = True
except ImportError:
    # Couldn't import the C extension, maybe it isn't built.
    if os.getenv("COVERAGE_CORE") == "ctrace":      # pragma: part covered
        # During testing, we use the COVERAGE_CORE environment variable
        # to indicate that we've fiddled with the environment to test this
        # fallback code.  If we thought we had a C tracer, but couldn't import
        # it, then exit quickly and clearly instead of dribbling confusing
        # errors. I'm using sys.exit here instead of an exception because an
        # exception here causes all sorts of other noise in unittest.
        sys.stderr.write("*** COVERAGE_CORE is 'ctrace' but can't import CTracer!\n")
        sys.exit(1)
    HAS_CTRACER = False


class Core:
    """Information about the central technology enabling execution measurement."""

    tracer_class: type[Tracer]
    tracer_kwargs: dict[str, Any]
    file_disposition_class: type[TFileDisposition]
    supports_plugins: bool
    packed_arcs: bool
    systrace: bool

    def __init__(self,
        warn: TWarnFn,
        timid: bool,
        metacov: bool,
    ) -> None:
        # Defaults
        self.tracer_kwargs = {}

        core_name: str | None
        if timid:
            core_name = "pytrace"
        else:
            core_name = os.getenv("COVERAGE_CORE")

            if core_name == "sysmon" and not env.PYBEHAVIOR.pep669:
                warn("sys.monitoring isn't available, using default core", slug="no-sysmon")
                core_name = None

            if not core_name:
                # Once we're comfortable with sysmon as a default:
                # if env.PYBEHAVIOR.pep669 and self.should_start_context is None:
                #     core_name = "sysmon"
                if HAS_CTRACER:
                    core_name = "ctrace"
                else:
                    core_name = "pytrace"

        if core_name == "sysmon":
            self.tracer_class = SysMonitor
            self.tracer_kwargs = {"tool_id": 3 if metacov else 1}
            self.file_disposition_class = FileDisposition
            self.supports_plugins = False
            self.packed_arcs = False
            self.systrace = False
        elif core_name == "ctrace":
            self.tracer_class = CTracer
            self.file_disposition_class = CFileDisposition
            self.supports_plugins = True
            self.packed_arcs = True
            self.systrace = True
        elif core_name == "pytrace":
            self.tracer_class = PyTracer
            self.file_disposition_class = FileDisposition
            self.supports_plugins = False
            self.packed_arcs = False
            self.systrace = True
        else:
            raise ConfigError(f"Unknown core value: {core_name!r}")
