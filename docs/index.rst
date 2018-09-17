.. Requests documentation master file, created by
   sphinx-quickstart on Sun Feb 13 23:54:25 2011.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Requests: HTTP for Humans™
==========================

Release v\ |version|. (:ref:`Installation <install>`)

.. image:: https://img.shields.io/pypi/l/requests.svg
    :target: https://pypi.org/project/requests/

.. image:: https://img.shields.io/pypi/wheel/requests.svg
    :target: https://pypi.org/project/requests/

.. image:: https://img.shields.io/pypi/pyversions/requests.svg
    :target: https://pypi.org/project/requests/

.. image:: https://codecov.io/github/requests/requests/coverage.svg?branch=master
    :target: https://codecov.io/github/requests/requests
    :alt: codecov.io

.. image:: https://img.shields.io/badge/Say%20Thanks!-🦉-1EAEDB.svg
    :target: https://saythanks.io/to/kennethreitz


**Requests** is the only *Non-GMO* HTTP library for Python, safe for human
consumption.

.. note:: The use of **Python 3** is *highly* preferred over Python 2. Consider upgrading your applications and infrastructure if you find yourself *still* using Python 2 in production today. If you are using Python 3, congratulations — you are indeed a person of excellent taste.
  —*Kenneth Reitz*
  
  
If you're interested in financially supporting Kenneth Reitz open source, consider visiting  `this link <https://cash.me/kennethreitz>`_. Your support helps tremendously with sustainability of motivation, as Open Source is no longer part of my day job.


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
    u'{"type":"User"...'
    >>> r.json()
    {u'private_gists': 419, u'total_private_repos': 77, ...}

See `similar code, sans Requests <https://gist.github.com/973705>`_.


**Requests** allows you to send *organic, grass-fed* HTTP/1.1 requests, without the
need for manual labor. There's no need to manually add query strings to your
URLs, or to form-encode your POST data. Keep-alive and HTTP connection pooling
are 100% automatic, thanks to `urllib3 <https://github.com/shazow/urllib3>`_.

User Testimonials
-----------------

Nike, Twitter, Spotify, Microsoft, Amazon, Lyft, BuzzFeed, Reddit, The NSA, Her Majesty's Government, Google, Twilio, Runscope, Mozilla, Heroku,
PayPal, NPR, Obama for America, Transifex, Native Instruments, The Washington
Post, SoundCloud, Kippt, Sony, and Federal U.S.
Institutions that prefer to be unnamed claim to use Requests internally.

**Armin Ronacher**, creator of Flask—
    *Requests is the perfect example how beautiful an API can be with the
    right level of abstraction.*

**Matt DeBoard**—
    *I'm going to get Kenneth Reitz's Python requests module tattooed
    on my body, somehow. The whole thing.*

**Daniel Greenfeld**—
    *Nuked a 1200 LOC spaghetti code library with 10 lines of code thanks to
    Kenneth Reitz's Requests library. Today has been AWESOME.*

**Kenny Meyers**—
    *Python HTTP: When in doubt, or when not in doubt, use Requests. Beautiful,
    simple, Pythonic.*

Requests is one of the most downloaded Python packages of all time, pulling in
over 400,000 downloads **each day**. Join the party!

If your organization uses Requests internally, consider `supporting the development of 3.0 <https://www.kennethreitz.org/requests3>`_. Your
generosity will be greatly appreciated, and help drive the project forward
into the future.

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

Requests officially supports Python 2.7 & 3.4–3.7, and runs great on PyPy.


The User Guide
--------------

This part of the documentation, which is mostly prose, begins with some
background information about Requests, then focuses on step-by-step
instructions for getting the most out of Requests.

.. toctree::
   :maxdepth: 2

   user/intro
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

   community/sponsors
   community/recommended
   community/faq
   community/out-there
   community/support
   community/vulnerabilities
   community/updates
   community/release-process

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
   dev/philosophy
   dev/todo
   dev/authors

There are no more guides. You are now guideless.
Good luck.
