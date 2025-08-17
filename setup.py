import sys

if sys.version_info < (3, 9):
    sys.stderr.write("Requests requires Python 3.9 or later.\n")
    sys.exit(1)

from setuptools import setup

setup()
