"""Fail CI if local CTX artifacts are tracked in the repository."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _git_lines(args: list[str]) -> list[str]:
    proc = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def _is_forbidden(path: str) -> bool:
    p = path.replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    return (
        p.startswith(".ctx/")
        or "/.ctx/" in p
        or p.endswith(".ctx")
        or base == "ops-telemetry.jsonl"
        or (base.endswith(".jsonl") and "ctx-mcp-telemetry" in base)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Block tracked CTX artifacts")
    parser.add_argument(
        "--mode",
        choices=["tracked", "staged", "all"],
        default="tracked",
    )
    args = parser.parse_args()

    tracked = _git_lines(["ls-files"])
    staged = _git_lines(["diff", "--cached", "--name-only"])
    tracked_hits = sorted({p for p in tracked if _is_forbidden(p)})
    staged_hits = sorted({p for p in staged if _is_forbidden(p)})

    fail = False
    if args.mode in {"tracked", "all"} and tracked_hits:
        fail = True
        print("Tracked forbidden files:")
        for p in tracked_hits:
            print(f"- {p}")
    if args.mode in {"staged", "all"} and staged_hits:
        fail = True
        print("Staged forbidden files:")
        for p in staged_hits:
            print(f"- {p}")

    if fail:
        print("CTX artifact guard: FAILED")
        return 1
    print("CTX artifact guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
