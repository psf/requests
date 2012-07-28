#!/usr/bin/env python

import os
import sys

import requests
from requests.compat import is_py2

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

packages = [
    'requests',
    'requests.packages',
    'requests.packages.urllib3',
    'requests.packages.urllib3.packages',
    'requests.packages.urllib3.packages.ssl_match_hostname'
]

if is_py2:
    packages.extend([
        'requests.packages.oauthlib',
        'requests.packages.oauthlib.oauth1',
        'requests.packages.oauthlib.oauth1.rfc5849',
        'requests.packages.oauthlib.oauth2',
        'requests.packages.oauthlib.oauth2.draft25',
        'requests.packages.chardet',
    ])
else:
    packages.append('requests.packages.chardet2')

requires = []

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
    package_data={'': ['LICENSE', 'NOTICE'], 'requests': ['*.pem']},
    package_dir={'requests': 'requests'},
    include_package_data=True,
    install_requires=requires,
    license=open('LICENSE').read(),
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
