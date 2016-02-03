Requests: HTTP for Humans
=========================

.. image:: https://img.shields.io/pypi/v/requests.svg
    :target: https://pypi.python.org/pypi/requests

.. image:: https://img.shields.io/pypi/dm/requests.svg
        :target: https://pypi.python.org/pypi/requests

Requests is the only *Non-GMO* HTTP library for Python, safe for human
consumption.

**Warning:** recreational use of other HTTP libraries may result in dangerous side-effects,
including: security vulnerabilities, verbose code, reinventing the wheel,
constantly reading documentation, depression, headaches, or even death.

.. code-block:: python

    >>> r = requests.get('https://api.github.com/user', auth=('user', 'pass'))
    >>> r.status_code
    200
    >>> r.headers['content-type']
    'application/json; charset=utf8'
    >>> r.encoding
    'utf-8'
    >>> r.text
    u'{"type":"User"...'
    >>> r.json()
    {u'disk_usage': 368627, u'private_gists': 484, ...}

See `the similar code, sans Requests <https://gist.github.com/973705>`_.

Requests allows you to send *organic, grass-fed* HTTP/1.1 requests, all day.
Headers, cookies, json/form data, multipart files, and url parameters can all
be provided with standard Python dictionaries. 
Responses feature RFC-compliant redirection history, unicode/bytes bodies, a
case-insensitive header dictionary, and more.


Special Features
----------------

- International Domains and URLs
- Keep-Alive & Connection Pooling
- Sessions with Cookie Persistence
- Browser-style SSL Verification
- Basic/Digest Authentication
- Elegant Key/Value Cookies
- Automatic Decompression
- Automatic Content Decoding
- Unicode Response Bodies
- Multipart File Uploads
- HTTP(S) proxy support
- Connection Timeouts
- Streaming Downloads
- Chunked Requests
- Thread-safety

Installation
------------

To install Requests, simply:

.. code-block:: bash

    $ pip install requests


Documentation
-------------

Documentation is available at http://docs.python-requests.org/.


Contribute
----------

#. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug. There is a `Contributor Friendly`_ tag for issues that should be ideal for people who are not very familiar with the codebase yet.
#. Fork `the repository`_ on GitHub to start making your changes to the **master** branch (or branch off of it).
#. Write a test which shows that the bug was fixed or that the feature works as expected.
#. Send a pull request and bug the maintainer until it gets merged and published. :) Make sure to add yourself to AUTHORS_.

.. _`the repository`: http://github.com/kennethreitz/requests
.. _AUTHORS: https://github.com/kennethreitz/requests/blob/master/AUTHORS.rst
.. _Contributor Friendly: https://github.com/kennethreitz/requests/issues?direction=desc&labels=Contributor+Friendly&page=1&sort=updated&state=open
