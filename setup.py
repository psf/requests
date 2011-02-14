#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

from distutils.core import setup


def publish():
	"""Publish to PyPi"""
	os.system("python setup.py sdist upload")

if sys.argv[-1] == "publish":
	publish()
	sys.exit()

required = []

# if python > 2.6, require simplejson

setup(
	name='requests',
	version='0.2.0',
	description='Python HTTP Library that\'s actually usable.',
	long_description=open('README.rst').read() + '\n\n' +
	                 open('HISTORY.rst').read(),
	author='Kenneth Reitz',
	author_email='me@kennethreitz.com',
	url='https://github.com/kennethreitz/requests',
	packages= [
		'requests',
	],
	install_requires=required,
	license='ISC',
	classifiers=(
		# 'Development Status :: 5 - Production/Stable',
		'Intended Audience :: Developers',
		'Natural Language :: English',
		'License :: OSI Approved :: MIT License',
		'Programming Language :: Python',
        # 'Programming Language :: Python :: 2.5',
        'Programming Language :: Python :: 2.6',
		'Programming Language :: Python :: 2.7',
		# 'Programming Language :: Python :: 3.0',
		# 'Programming Language :: Python :: 3.1',
	),
)
