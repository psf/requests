#!/usr/bin/env python
# Learn more: https://github.com/kennethreitz/setup.py
import ast
import os
import re
import sys

from codecs import open

from setuptools import setup
from setuptools.command.test import test as TestCommand

here = os.path.abspath(os.path.dirname(__file__))

class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass into py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        try:
            from multiprocessing import cpu_count
            self.pytest_args = ['-n', str(cpu_count()), '--boxed']
        except (ImportError, NotImplementedError):
            self.pytest_args = ['-n', '1', '--boxed']

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)

# 'setup.py publish' shortcut.
if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist bdist_wheel')
    os.system('twine upload dist/*')
    sys.exit()


def extract_global_vars(t):
    m = ast.parse(t)
    res = {}
    for s in m.body:
        if isinstance(s, ast.Assign):
            try:
                v = ast.literal_eval(s.value)
                for t in s.targets:
                    if isinstance(t, ast.Name):
                        res[t.id] = v
            except ValueError:
                continue

    return res

def get_about():
    with open(os.path.join(here, 'requests', '__version__.py'), 'r', 'utf-8') as f:
        return extract_global_vars(f.read())


about = get_about()

setup(
    name=about['__title__'],
    version=about['__version__'],
    description=about['__description__'],
    author=about['__author__'],
    author_email=about['__author_email__'],
    url=about['__url__'],
    license=about['__license__'],
    cmdclass={'test': PyTest},
)
