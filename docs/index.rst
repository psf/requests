.. Requests documentation master file, created by
   sphinx-quickstart on Sun Feb 13 23:54:25 2011.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Requests: HTTP for Humans
=========================

Release v\ |version|. (:ref:`Installation <install>`)

Requests is an :ref:`ISC Licensed <isc>` HTTP library, written in Python, for human beings.

Python's standard **urllib2** module provides most of
the HTTP capabilities you need, but the API is thoroughly **broken**.
It was built for a different time — and a different web. It requires an *enormous* amount of work (even method overrides) to perform the simplest of tasks.

Things shouldn’t be this way. Not in Python.

::

    >>> r = requests.get('https://api.github.com/user', auth=('user', 'pass'))
    >>> r.status_code
    200
    >>> r.headers['content-type']
    'application/json; charset=utf8'
    >>> r.encoding
    'utf-8'
    >>> r.text
    u'{"type":"User"...'
    >>> r.json
    {u'private_gists': 419, u'total_private_repos': 77, ...}

See `similar code, without Requests <https://gist.github.com/973705>`_.

Requests takes all of the work out of Python HTTP/1.1 — making your integration with web services seamless. There's no need to manually add query strings to your URLs, or to form-encode your POST data. Keep-alive and HTTP connection pooling are 100%  automatic, powered by `urllib3 <https://github.com/shazow/urllib3>`_, which is embedded within Requests.


Testimonials
------------

`Kippt <http://kippt.com>`_, `Heroku <http://heroku.com>`_, `PayPal <https://www.paypal.com/>`_,
`Transifex <https://www.transifex.net/>`_,
`Native Instruments <http://www.native-instruments.com/>`_, `The Washington Post <http://www.washingtonpost.com/>`_,
`Twitter, Inc <http://twitter.com>`_,
`Readability <http://readability.com>`_, and
Federal US Institutions
use Requests internally. It has been installed over 100,000 times from PyPI.

**Armin Ronacher**
    Requests is the perfect example how beautiful an API can be with the
    right level of abstraction.

**Matt DeBoard**
    I'm going to get @kennethreitz's Python requests module tattooed
    on my body, somehow. The whole thing.

**Daniel Greenfeld**
    Nuked a 1200 LOC spaghetti code library with 10 lines of code thanks to
    @kennethreitz's request library. Today has been AWESOME.

**Kenny Meyers**
    Python HTTP: When in doubt, or when not in doubt, use Requests. Beautiful,
    simple, Pythonic.


Feature Support
---------------

Requests is ready for today's web.

- International Domains and URLs
- Keep-Alive & Connection Pooling
- Sessions with Cookie Persistence
- Browser-style SSL Verification
- Basic/Digest Authentication
- Elegant Key/Value Cookies
- Automatic Decompression
- Unicode Response Bodies
- Multipart File Uploads
- Connection Timeouts
- ``.netrc`` support
- Thread-safe.


User Guide
----------

This part of the documentation, which is mostly prose, begins with some
background information about Requests, then focuses on step-by-step
instructions for getting the most out of Requests.

.. toctree::
   :maxdepth: 2

   user/intro
   user/install
   user/quickstart
   user/advanced


Community Guide
-----------------

This part of the documentation, which is mostly prose, details the
Requests ecosystem and community.

.. toctree::
   :maxdepth: 1

   community/faq
   community/out-there.rst
   community/support
   community/updates

API Documentation
-----------------

If you are looking for information on a specific function, class or method,
this part of the documentation is for you.

.. toctree::
   :maxdepth: 2

   api


Developer Guide
---------------

If you want to contribute to the project, this part of the documentation is for
you.

.. toctree::
   :maxdepth: 1

   dev/internals
   dev/todo
   dev/authors
