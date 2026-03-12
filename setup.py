import sys

if sys.version_info < (3, 10):  # noqa: UP036
    sys.stderr.write("Requests requires Python 3.10 or later.\n")
    sys.exit(1)

from setuptools import setup

setup()
