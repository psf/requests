# -*- coding: utf-8 -*-

"""
    requests.core
    ~~~~~~~~~~~~~

    This module implements the main Requests system.

    :copyright: (c) 2011 by Kenneth Reitz.
    :license: ISC, see LICENSE for more details.
"""

import httplib
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
		"""Sends the request. """
		#set self.response
		# return True / False
		pass
		
	
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
	# return response object

def head(url, params={}, headers={}, auth=None):
	pass
	# return response object

def post(url, params={}, headers={}, auth=None):
	pass
	# return response object
	
def put(url, data='', headers={}, auth=None):
	pass
	# return response object
	
def delete(url, params={}, headers={}, auth=None):
	pass
	# return response object


def add_autoauth(url, authobject):
	global AUTHOAUTHS
	
	AUTHOAUTHS.append((url, authobject))
	



class RequestException(Exception):
	"""There was an ambiguous exception that occured while handling your request."""

class AuthenticationError(RequestException):
	"""The authentication credentials provided were invalid."""
	
class URLRequired(RequestException):
	"""A valid URL is required to make a request."""
	
class InvalidMethod(RequestException):
	"""An inappropriate method was attempted."""
	