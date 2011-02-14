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


__title__ = 'requests'
__version__ = '0.2.0'
__build__ = 0x000200
__author__ = 'Kenneth Reitz'
__license__ = 'ISC'
__copyright__ = 'Copyright 2011 Kenneth Reitz'


AUTOAUTHS = []


class _Request(urllib2.Request):
    def __init__(self, url, data=None, headers={},
                 origin_req_host=None, unverifiable=False, method=None):
       urllib2.Request.__init__(self, url, data, headers, origin_req_host, unverifiable)
       self.method = method

    def get_method(self):
        if self.method:
            return self.method

        return urllib2.Request.get_method(self)


class Request(object):
	"""The :class:`Request` object. It's awesome.
	"""
	
	_METHODS = ('GET', 'HEAD', 'PUT', 'POST', 'DELETE')
	
	def __init__(self):
		self.url = None
		self.headers = dict()
		self.method = None
		self.params = {}
		self.data = {}
		self.response = Response()
		self.auth = None
		self.sent = False
		
	
	def __setattr__(self, name, value):
		if (name == 'method') and (value):
			if not value in self._METHODS:
				raise InvalidMethod()
		
		object.__setattr__(self, name, value)
	
	
	def _checks(self):
		"""Deterministic checks for consistiency."""

		if not self.url:
			raise URLRequired

		
	def _get_opener(self):
		""" Creates appropriate opener object for urllib2.
		"""
		
		if self.auth:

			# create a password manager
			authr = urllib2.HTTPPasswordMgrWithDefaultRealm()

			authr.add_password(None, self.url, self.auth.username, self.auth.password)
			handler = urllib2.HTTPBasicAuthHandler(authr)
			opener = urllib2.build_opener(handler)

			# use the opener to fetch a URL
			return opener.open
		else:
			return urllib2.urlopen

	
	def send(self, anyway=False):
		"""Sends the request. 
		
		   :param anyway: If True, request will be sent, even if it has already been sent.
		"""
		self._checks()

		success = False
		
		if self.method in ('GET', 'HEAD', 'DELETE'):
			if (not self.sent) or anyway:

				# url encode GET params if it's a dict
				if isinstance(self.params, dict):
					params = urllib.urlencode(self.params)
				else:

					params = self.params

				req = _Request(("%s?%s" % (self.url, params)), method=self.method)

				if self.headers:
					req.headers = self.headers

				opener = self._get_opener()

				try:
					resp = opener(req)
					self.response.status_code = resp.code
					self.response.headers = resp.info().dict
					if self.method.lower() == 'get':
						self.response.content = resp.read()

					success = True
				except urllib2.HTTPError, why:
					self.response.status_code = why.code


		elif self.method == 'PUT':
			if (not self.sent) or anyway:

				req = _Request(self.url, method='PUT')

				if self.headers:
					req.headers = self.headers

				req.data = self.data

				try:
					opener = self._get_opener()
					resp =  opener(req)

					self.response.status_code = resp.code
					self.response.headers = resp.info().dict
					self.response.content = resp.read()

					success = True

				except urllib2.HTTPError, why:
					self.response.status_code = why.code




		elif self.method == 'POST':
			if (not self.sent) or anyway:

				req = _Request(self.url, method='POST')

				if self.headers:
					req.headers = self.headers

				# url encode form data if it's a dict
				if isinstance(self.data, dict):
					req.data = urllib.urlencode(self.data)
				else:
					req.data = self.data

				try:

					opener = self._get_opener()
					resp =  opener(req)

					self.response.status_code = resp.code
					self.response.headers = resp.info().dict
					self.response.content = resp.read()

					success = True

				except urllib2.HTTPError, why:
					self.response.status_code = why.code

		
		self.sent = True if success else False
		
		return success
		

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
	"""Sends a GET request. Returns :class:`Response` object.
	"""
	r = Request()
	
	r.method = 'GET'
	r.url = url
	r.params = params
	r.headers = headers
	r.auth = _detect_auth(url, auth)
	
	r.send()
	
	return r.response


def head(url, params={}, headers={}, auth=None):
	"""Sends a HEAD request. Returns :class:`Response` object.
	"""
	r = Request()
	
	r.method = 'HEAD'
	r.url = url
	# return response object
	r.params = params
	r.headers = headers
	r.auth = _detect_auth(url, auth)
	
	r.send()
	
	return r.response


def post(url, data={}, headers={}, auth=None):
	"""Sends a POST request. Returns :class:`Response` object.
	"""
	r = Request()

	r.url = url
	r.method = 'POST'
	r.data = data
	
	r.headers = headers
	r.auth = _detect_auth(url, auth)
	
	r.send()
	
	return r.response
	
	
def put(url, data='', headers={}, auth=None):
	"""Sends a PUT request. Returns :class:`Response` object.
	"""
	r = Request()

	r.url = url
	r.method = 'PUT'
	r.data = data
	
	r.headers = headers
	r.auth = _detect_auth(url, auth)
	
	r.send()
	
	return r.response

	
def delete(url, params={}, headers={}, auth=None):
	"""Sends a DELETE request. Returns :class:`Response` object.
	"""
	r = Request()

	r.url = url
	r.method = 'DELETE'
	# return response object
	
	r.headers = headers
	r.auth = _detect_auth(url, auth)
	
	r.send()
	
	return r.response


def add_autoauth(url, authobject):
	global AUTOAUTHS
	
	AUTOAUTHS.append((url, authobject))


def _detect_auth(url, auth):

	return _get_autoauth(url) if not auth else auth

	
def _get_autoauth(url):
	for (autoauth_url, auth) in AUTOAUTHS:
		if autoauth_url in url: 
			return auth
			
	return None

class RequestException(Exception):
	"""There was an ambiguous exception that occured while handling your request."""

class AuthenticationError(RequestException):
	"""The authentication credentials provided were invalid."""
	
class URLRequired(RequestException):
	"""A valid URL is required to make a request."""
	
class InvalidMethod(RequestException):
	"""An inappropriate method was attempted."""
