.. Requests documentation master file, created by
   sphinx-quickstart on Sun Feb 13 23:54:25 2011.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Requests: HTTP for Humans™
==========================

Release v\ |version|. (:ref:`Installation <install>`)


.. image:: https://pepy.tech/badge/requests/month
    :target: https://pepy.tech/project/requests
    :alt: Requests Downloads Per Month Badge
    
.. image:: https://img.shields.io/pypi/l/requests.svg
    :target: https://pypi.org/project/requests/
    :alt: License Badge

.. image:: https://img.shields.io/pypi/wheel/requests.svg
    :target: https://pypi.org/project/requests/
    :alt: Wheel Support Badge

.. image:: https://img.shields.io/pypi/pyversions/requests.svg
    :target: https://pypi.org/project/requests/
    :alt: Python Version Support Badge

**Requests** is an elegant and simple HTTP library for Python, built for human beings.

-------------------

**Behold, the power of Requests**::

    >>> r = requests.get('https://api.github.com/user', auth=('user', 'pass'))
    >>> r.status_code
    200
    >>> r.headers['content-type']
    'application/json; charset=utf8'
    >>> r.encoding
    'utf-8'
    >>> r.text
    '{"type":"User"...'
    >>> r.json()
    {'private_gists': 419, 'total_private_repos': 77, ...}

See `similar code, sans Requests <https://gist.github.com/973705>`_.


**Requests** allows you to send HTTP/1.1 requests extremely easily. 
There's no need to manually add query strings to your
URLs, or to form-encode your POST data. Keep-alive and HTTP connection pooling
are 100% automatic, thanks to `urllib3 <https://github.com/urllib3/urllib3>`_.

Beloved Features
----------------

Requests is ready for today's web.

- Keep-Alive & Connection Pooling
- International Domains and URLs
- Sessions with Cookie Persistence
- Browser-style SSL Verification
- Automatic Content Decoding
- Basic/Digest Authentication
- Elegant Key/Value Cookies
- Automatic Decompression
- Unicode Response Bodies
- HTTP(S) Proxy Support
- Multipart File Uploads
- Streaming Downloads
- Connection Timeouts
- Chunked Requests
- ``.netrc`` Support

Requests officially supports Python 2.7 & 3.6+, and runs great on PyPy.


The User Guide
--------------

This part of the documentation, which is mostly prose, begins with some
background information about Requests, then focuses on step-by-step
instructions for getting the most out of Requests.

.. toctree::
   :maxdepth: 2

   user/install
   user/quickstart
   user/advanced
   user/authentication


The Community Guide
-------------------

This part of the documentation, which is mostly prose, details the
Requests ecosystem and community.

.. toctree::
   :maxdepth: 2

   community/recommended
   community/faq
   community/out-there
   community/support
   community/vulnerabilities
   community/release-process

.. toctree::
   :maxdepth: 1

   community/updates

The API Documentation / Guide
-----------------------------

If you are looking for information on a specific function, class, or method,
this part of the documentation is for you.

.. toctree::
   :maxdepth: 2

   api


The Contributor Guide
---------------------

If you want to contribute to the project, this part of the documentation is for
you.

.. toctree::
   :maxdepth: 3

   dev/contributing
   dev/authors

There are no more guides. You are now guideless.
Good luck.
