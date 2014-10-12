#!/usr/bin/env python

import os
import sys

#import requests

from codecs import open

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()

packages = [
    'yieldfrom',
    'yieldfrom.requests',
    #'yieldfrom.requests.packages',
    #'yieldfrom.requests.packages.chardet',
    #'yieldfrom.requests.packages.urllib3',
    #'yieldfrom.requests.packages.urllib3.packages',
    #'yieldfrom.requests.packages.urllib3.contrib',
    #'yieldfrom.requests.packages.urllib3.util',
    #'yieldfrom.requests.packages.urllib3.packages.ssl_match_hostname',
]

requires = [] # TODO change this

with open('README.rst', 'r', 'utf-8') as f:
    readme = f.read()
with open('HISTORY.rst', 'r', 'utf-8') as f:
    history = f.read()

setup(
    name='requests',
    version='0.1',
    description='asyncio Python HTTP for Humans.',
    long_description=readme + '\n\n' + history,

    author='Kenneth Reitz',
    author_email='me@kennethreitz.com',
    maintainer='David Keeney',
    maintainer_email='dkeeney@rdbhost.com',

    url='http://github.com/rdbhost/yieldfromrequests',

    packages=packages,
    package_data={'': ['LICENSE', 'NOTICE'], 'requests': ['*.pem']},
    package_dir={'requests': 'requests'},
    include_package_data=True,
    namespace_packages=['yieldfrom'],
    install_requires=requires,

    license='Apache 2.0',
    zip_safe=False,
    classifiers=(
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4'

    ),
    extras_require={
        'security': ['pyOpenSSL', 'ndg-httpsclient', 'pyasn1'],
    },
)
