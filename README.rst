Requests: The Simple (e.g. usable) HTTP Module
==============================================

Most existing Python modules for dealing HTTP requests are insane. I have to look up *everything* that I want to do. Most of my worst Python experiences are a result of the various built-in HTTP libraries (yes, even worse than Logging). 

But this one's different. This one's going to be awesome. And simple.

Really simple. 

Features
--------

- Extremely simple GET, HEAD, POST, PUT, DELETE Requests
    + Simple HTTP Header Request Attachment
    + Simple Data/Params Request Attachment
    + Simple Multipart File Uploads
    + CookieJar Support
    
- Simple Basic HTTP Authentication
    + Simple URL + HTTP Auth Registry


Usage
-----

It couldn't be simpler. ::

    >>> import requests
    >>> r = requests.get('http://google.com')


HTTPS? Basic Authentication? ::
    
    >>> r = requests.get('https://convore.com/api/account/verify.json')
    >>> r.status_code
    401

    
Uh oh, we're not authorized! Let's add authentication. ::
    
    >>> conv_auth = requests.AuthObject('requeststest', 'requeststest')
    >>> r = requests.get('https://convore.com/api/account/verify.json', auth=conv_auth)
    
    >>> r.status_code
    200 
    
    >>> r.headers['content-type']
    'application/json'
    
    >>> r.content
    '{"username": "requeststest", "url": "/users/requeststest/", "id": "9408", "img": "censored-long-url"}'



API
---
    
**Requests:**

All request functions return a Response object (see below).

If a {filename: fileobject} dictionary is passed in (files=...), a multipart_encode upload will be performed.
If CookieJar object is is passed in (cookies=...), the cookies will be sent with the request.
    
  GET Requests
    >>> request.get(url, params={}, headers={}, cookies=None, auth=None)
    <request object>
    
  HEAD Requests
    >>> request.head(url, params={}, headers={}, cookies=None, auth=None)
    <request object>
    
  PUT Requests
    >>> request.put(url, data='', headers={}, files={}, cookies=None, auth=None)
    <request object>
    
  POST Requests
    >>> request.post(url, data={}, headers={}, files={}, cookies=None, auth=None)
    <request object>
    
  DELETE Requests
    >>> request.delete(url, params={}, headers={}, cookies=None, auth=None)
    <request object>
    

**Responses:**
    
    Request.status_code:
         (Integer) Received HTTP Status Code Response

    Request.headers:
        (Dictionary) Received HTTP Response Headers

    Request.content:
        (Bytes) Received Content

    Request.url
        (String) URL of response. Useful for detecting redirects. 


**HTTP Authentication Registry:**

    You can register AuthObjects to automatically enable HTTP Authentication on requests that contain a registered base URL string.

    >>> requests.add_autoauth(url, authobject)



Installation
------------

To install requests, simply: ::

    $ pip install requests
    
Or, if you absolutely must: ::

    $ easy_install requests

But, you really shouldn't do that.
   


Contribute
----------

If you'd like to contribute, simply fork `the repository`_, commit your changes to the **develop** branch (or branch off of it), and send a pull request. Make sure you add yourself to AUTHORS_.



Roadmap
-------

- Sphinx Documentation
- Exhaustive Unittests

.. _`the repository`: http://github.com/kennethreitz/requests
.. _AUTHORS: http://github.com/kennethreitz/requests/blob/master/AUTHORS
