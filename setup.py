#!/usr/bin/env python

"""
distutils/setuptools install script. See inline comments for packaging documentation.
"""

import os
import sys

import requests
from requests.compat import is_py3

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()

packages = [
    'requests',
    'requests.packages',
    'requests.packages.urllib3',
    'requests.packages.urllib3.packages',
    'requests.packages.urllib3.packages.ssl_match_hostname',
    'requests.packages.urllib3.packages.mimetools_choose_boundary',
]

# certifi is a Python package containing a CA certificate bundle for SSL verification.
# On certain supported platforms (e.g., Red Hat / Debian / FreeBSD), Requests can
# use the system CA bundle instead; see `requests.utils` for details.
# If your platform is supported, set `requires` to [] instead:
requires = ['certifi>=0.0.7']

# chardet is used to optimally guess the encodings of pages that don't declare one.
# At this time, chardet is not a required dependency. However, it's sufficiently
# important that pip/setuptools should install it when it's unavailable.
if is_py3:
    chardet_package = 'chardet2'
else:
    chardet_package = 'chardet>=1.0.0'
    requires.append('oauthlib>=0.1.0,<0.2.0')

requires.append(chardet_package)

# The async API in requests.async requires the gevent package.
# This is also not a required dependency.
extras_require = {
        'async': ['gevent'],
}

setup(
    name='requests',
    version=requests.__version__,
    description='Python HTTP for Humans.',
    long_description=open('README.rst').read() + '\n\n' +
                     open('HISTORY.rst').read(),
    author='Kenneth Reitz',
    author_email='me@kennethreitz.com',
    url='http://python-requests.org',
    packages=packages,
    package_data={'': ['LICENSE', 'NOTICE']},
    include_package_data=True,
    install_requires=requires,
    extras_require=extras_require,
    license=open("LICENSE").read(),
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.0',
        'Programming Language :: Python :: 3.1',
    ),
)
