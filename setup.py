import sys

if __name__ == "__main__":
    if sys.version_info < (3, 9):
        sys.stderr.write("Requests requires Python 3.9 or later.\n")
        sys.exit(1)
    try:
        import hatchling  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "This package now uses pyproject.toml and PEP 517 for builds. "
            "Please upgrade pip (>=21.3) and setuptools.\n"
        )
        sys.exit(1)

    from setuptools import setup

    setup()
