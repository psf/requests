# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/nedbat/coveragepy/blob/master/NOTICE.txt

"""Invasive patches for coverage.py."""

from __future__ import annotations

import atexit
import contextlib
import os
import site
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

from coverage import env
from coverage.debug import NoDebugging, DevNullDebug
from coverage.exceptions import ConfigError, CoverageException

if TYPE_CHECKING:
    from coverage import Coverage
    from coverage.config import CoverageConfig
    from coverage.types import TDebugCtl


def apply_patches(
    cov: Coverage,
    config: CoverageConfig,
    debug: TDebugCtl,
    *,
    make_pth_file: bool = True,
) -> None:
    """Apply invasive patches requested by `[run] patch=`."""
    debug = debug if debug.should("patch") else DevNullDebug()
    for patch in sorted(set(config.patch)):
        match patch:
            case "_exit":
                _patch__exit(cov, debug)

            case "execv":
                _patch_execv(cov, config, debug)

            case "fork":
                _patch_fork(debug)

            case "subprocess":
                _patch_subprocess(config, debug, make_pth_file)

            case _:
                raise ConfigError(f"Unknown patch {patch!r}")


def _patch__exit(cov: Coverage, debug: TDebugCtl) -> None:
    """Patch os._exit."""
    debug.write("Patching _exit")

    old_exit = os._exit

    def coverage_os_exit_patch(status: int) -> NoReturn:
        with contextlib.suppress(Exception):
            debug.write(f"Using _exit patch with {cov = }")
        with contextlib.suppress(Exception):
            cov.save()
        old_exit(status)

    os._exit = coverage_os_exit_patch


def _patch_execv(cov: Coverage, config: CoverageConfig, debug: TDebugCtl) -> None:
    """Patch the execv family of functions."""
    if env.WINDOWS:
        raise CoverageException("patch=execv isn't supported yet on Windows.")

    debug.write("Patching execv")

    def make_execv_patch(fname: str, old_execv: Any) -> Any:
        def coverage_execv_patch(*args: Any, **kwargs: Any) -> Any:
            with contextlib.suppress(Exception):
                debug.write(f"Using execv patch for {fname} with {cov = }")
            with contextlib.suppress(Exception):
                cov.save()

            if fname.endswith("e"):
                # Assume the `env` argument is passed positionally.
                new_env = args[-1]
                # Pass our configuration in the new environment.
                new_env["COVERAGE_PROCESS_CONFIG"] = config.serialize()
                if env.TESTING:
                    # The subprocesses need to use the same core as the main process.
                    new_env["COVERAGE_CORE"] = os.getenv("COVERAGE_CORE")

                    # When testing locally, we need to honor the pyc file location
                    # or they get written to the .tox directories and pollute the
                    # next run with a different core.
                    if (cache_prefix := os.getenv("PYTHONPYCACHEPREFIX")) is not None:
                        new_env["PYTHONPYCACHEPREFIX"] = cache_prefix

                    # Without this, it fails on PyPy and Ubuntu.
                    new_env["PATH"] = os.getenv("PATH")
            old_execv(*args, **kwargs)

        return coverage_execv_patch

    # All the exec* and spawn* functions eventually call execv or execve.
    os.execv = make_execv_patch("execv", os.execv)
    os.execve = make_execv_patch("execve", os.execve)


def _patch_fork(debug: TDebugCtl) -> None:
    """Ensure Coverage is properly reset after a fork."""
    from coverage.control import _after_fork_in_child

    if env.WINDOWS:
        raise CoverageException("patch=fork isn't supported yet on Windows.")

    debug.write("Patching fork")
    os.register_at_fork(after_in_child=_after_fork_in_child)


def _patch_subprocess(config: CoverageConfig, debug: TDebugCtl, make_pth_file: bool) -> None:
    """Write .pth files and set environment vars to measure subprocesses."""
    debug.write("Patching subprocess")

    if make_pth_file:
        pth_files = create_pth_files(debug)

        def delete_pth_files() -> None:
            for p in pth_files:
                debug.write(f"Deleting subprocess .pth file: {str(p)!r}")
                p.unlink(missing_ok=True)

        atexit.register(delete_pth_files)
    assert config.config_file is not None
    os.environ["COVERAGE_PROCESS_CONFIG"] = config.serialize()


# Writing .pth files is not obvious. On Windows, getsitepackages() returns two
# directories.  A .pth file in the first will be run, but coverage isn't
# importable yet.  We write into all the places we can, but with defensive
# import code.

PTH_CODE = """\
try:
    import coverage
except:
    pass
else:
    coverage.process_startup()
"""

PTH_TEXT = f"import sys; exec({PTH_CODE!r})\n"


def create_pth_files(debug: TDebugCtl = NoDebugging()) -> list[Path]:
    """Create .pth files for measuring subprocesses."""
    pth_files = []
    for pth_dir in site.getsitepackages():
        pth_file = Path(pth_dir) / f"subcover_{os.getpid()}.pth"
        try:
            if debug.should("patch"):
                debug.write(f"Writing subprocess .pth file: {str(pth_file)!r}")
            pth_file.write_text(PTH_TEXT, encoding="utf-8")
        except OSError:  # pragma: cant happen
            continue
        else:
            pth_files.append(pth_file)
    return pth_files
