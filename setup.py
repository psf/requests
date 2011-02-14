#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

from distutils.core import setup


	
if sys.argv[-1] == "publish":
	os.system("python setup.py sdist upload")
	sys.exit()

if sys.argv[-1] == "test":
	os.system("python test_requests.py")
	sys.exit()
	
required = []

# if python > 2.6, require simplejson

setup(
	name='requests',
	version='0.2.2',
	description='Awesome Python HTTP Library that\'s actually usable.',
	long_description=open('README.rst').read() + '\n\n' +
	                 open('HISTORY.rst').read(),
	author='Kenneth Reitz',
	author_email='me@kennethreitz.com',
	url='https://github.com/kennethreitz/requests',
	packages= [
		'requests',
		'requests.packages',
		'requests.packages.poster'
	],
	install_requires=required,
	license='ISC',
	classifiers=(
		# 'Development Status :: 5 - Production/Stable',
		'Intended Audience :: Developers',
		'Natural Language :: English',
		'License :: OSI Approved :: ISC License (ISCL)',
		'Programming Language :: Python',
        # 'Programming Language :: Python :: 2.5',
        'Programming Language :: Python :: 2.6',
		'Programming Language :: Python :: 2.7',
		# 'Programming Language :: Python :: 3.0',
		# 'Programming Language :: Python :: 3.1',
	),
)
