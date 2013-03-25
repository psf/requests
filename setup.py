#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import requesocks

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()


required = ['certifi>=0.0.7',]
packages = [
    'requesocks',
    'requesocks.packages',
    'requesocks.packages.urllib3',
    'requesocks.packages.urllib3.packages',
    'requesocks.packages.urllib3.packages.ssl_match_hostname',
    'requesocks.packages.urllib3.packages.socksipy',
    'requesocks.packages.urllib3.packages.mimetools_choose_boundary',
]

required.append('chardet>=1.0.0')
packages.append('requesocks.packages.oreos')


setup(
    name='requesocks',
    version=requesocks.__version__,
    description='Python HTTP for Humans, with socks proxy support',
    long_description=open('README.rst').read() + '\n\n' +
                     open('HISTORY.rst').read(),
    author='Kenneth Reitz',
    author_email='me@kennethreitz.com',
    url='http://python-requests.org',
    packages=packages,
    package_data={'': ['LICENSE', 'NOTICE']},
    include_package_data=True,
    install_requires=required,
    license='ISC',
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ),
)
