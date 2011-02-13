# -*- coding: utf-8 -*-

"""
    requests.core
    ~~~~~~~~~~~~~

    This module implements the main Requests system.

    :copyright: (c) 2011 by Kenneth Reitz.
    :license: ISC, see LICENSE for more details.
"""
import urllib
import urllib2


__title__ = 'convore'
__version__ = '0.0.1'
__build__ = 0x000001
__author__ = 'Kenneth Reitz'
__license__ = 'ISC'
__copyright__ = 'Copyright 2011 Kenneth Reitz'


AUTHOAUTHS = []


class Request(object):
	"""The :class:`Request` object. It's awesome.
	"""
	
	_METHODS = ('get', 'put', 'post', 'delete')
	
	def __init__(self):
		self.headers = dict()
		self.method = None
		self.response = None
	
	def __setattr__(self, key, val):
		if key == 'method':
			if not val.lower() in _METHODS:
				raise InvalidMethod()
		
	def send(self):
		pass
		set self.response()
		# return True / False
		
	
class Response(object):
	"""The :class:`Request` object. It's awesome.
	"""
	
	def __init__(self):
		self.content = None
		self.status_code = None
		self.headers = dict()
		
	
class AuthObject(object):
	"""The :class:`AuthObject` is a simple HTTP Authentication token.
	
	:param username: Username to authenticate with.
    :param password: Password for given username.
	 """
	
	def __init__(self, username, password):
		self.username = username
		self.password = password


def get(url, params={}, headers={}, auth=None):
	pass

def head(url, params={}, headers={}, auth=None):
	pass

def post(url, params={}, headers={}, auth=None):
	pass
	
def put(url, data='', headers={}, auth=None):
	pass
	
def delete(url, params={}, headers={}, auth=None):
	pass


def add_autoauth(url, authobject):
	global AUTHOAUTHS
	
	AUTHOAUTHS.append((url, authobject))
	
	
class InvalidMethod(Exception):
	"""An innappropriate method was attempted."""