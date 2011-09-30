#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import requests

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup



if 'publish' in sys.argv:
    os.system('python setup.py sdist upload')
    sys.exit()

if 'test' in sys.argv:
    os.system('python test_requests.py')
    sys.exit()

required = []

setup(
    name='requests',
    version=requests.__version__,
    description='Python HTTP for Humans.',
    long_description=open('README.rst').read() + '\n\n' +
                     open('HISTORY.rst').read(),
    author='Kenneth Reitz',
    author_email='me@kennethreitz.com',
    url='http://python-requests.org',
    packages= [
        'requests',
        'requests.packages',
        'requests.packages.urllib3'
    ],
    install_requires=required,
    license='ISC',
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.5',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        # 'Programming Language :: Python :: 3.0',
        # 'Programming Language :: Python :: 3.1',
    ),
)
