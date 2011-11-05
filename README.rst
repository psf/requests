Requests: HTTP for Humans
=========================

Requests is an ISC Licensed HTTP library, written in Python, for human
beings.

Most existing Python modules for sending HTTP requests are extremely
verbose and cumbersome. Python's builtin urllib2 module provides most of
the HTTP capabilities you should need, but the api is thoroughly broken.
It requires an enormous amount of work (even method overrides) to
perform the simplest of tasks.

Things shouldn't be this way. Not in Python.

::

    >>> r = requests.get('https://api.github.com', auth=('user', 'pass'))
    >>> r.status_code
    204
    >>> r.headers['content-type']
    'application/json'
    >>> r.content
    ...

See `the same code, without Requests <https://gist.github.com/973705>`_.

Requests allow you to send  **HEAD**, **GET**, **POST**, **PUT**,
**PATCH**, and **DELETE** HTTP requests. You can add headers, form data,
multipart files, and parameters with simple Python dictionaries, and access the
response data in the same way. It's powered by urllib2, but it does
all the hard work and crazy hacks for you.


Features
--------

- Extremely simple HEAD, GET, POST, PUT, PATCH, DELETE Requests.
- Gevent support for Asyncronous Requests.
- Sessions with cookie persistience.
- Basic, Digest, and Custom Authentication support.
- Automatic form-encoding of dictionaries
- A simple dictionary interface for request/response cookies.
- Multipart file uploads.
- Automatc decoding of Unicode, gzip, and deflate responses.
- Full support for unicode URLs and domain names.


Usage
-----

It couldn't be simpler. ::

    >>> import requests
    >>> r = requests.get('http://google.com')


HTTPS? Basic Authentication? ::

    >>> r = requests.get('https://httpbin.ep.io/basic-auth/user/pass')
    >>> r.status_code
    401


Uh oh, we're not authorized! Let's add authentication. ::

    >>> r = requests.get('https://httpbin.ep.io/basic-auth/user/pass', auth=('user', 'pass'))

    >>> r.status_code
    200

    >>> r.headers['content-type']
    'application/json'

    >>> r.content
    '{"authenticated": true, "user": "user"}'


Installation
------------

To install requests, simply: ::

    $ pip install requests

Or, if you absolutely must: ::

    $ easy_install requests

But, you really shouldn't do that.



Contribute
----------

#. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug. There is a Contributor Friendly tag for issues that should be ideal for people who are not very familiar with the codebase yet.
#. Fork `the repository`_ on Github to start making your changes to the **develop** branch (or branch off of it).
#. Write a test which shows that the bug was fixed or that the feature works as expected.
#. Send a pull request and bug the maintainer until it gets merged and published. :) Make sure to add yourself to AUTHORS_.

.. _`the repository`: http://github.com/kennethreitz/requests
.. _AUTHORS: http://github.com/kennethreitz/requests/blob/master/AUTHORS
