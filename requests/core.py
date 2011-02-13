# -*- coding: utf-8 -*-

"""
    requests.core
    ~~~~~~~~~~~~~

    This module implements the main Requests system.

    :copyright: (c) 2011 by Kenneth Reitz.
    :license: ISC, see LICENSE for more details.
"""
import urllib2


__title__ = 'convore'
__version__ = '0.0.1'
__build__ = 0x000001
__author__ = 'Kenneth Reitz'
__license__ = 'ISC'
__copyright__ = 'Copyright 2011 Kenneth Reitz'


class Request(object):
	"""The :class:`Request` object. It's awesome.
	"""
	pass
	
	
class Response(object):
	"""The :class:`Request` object. It's awesome.
	"""
	
class AuthObject(object):
	"""The :class:`AuthObject` is a simple HTTP Authentication token.
	
	:param username: Username to authenticate with.
    :param password: Password for given username.
	 """
	
	def __init__(self, username, password):
		self.username = username
		self.password = password


def get():
	pass

def post():
	pass
	
def put():
	pass
	
def delete():
	pass
	
