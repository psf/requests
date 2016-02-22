.. Requests documentation master file, created by
   sphinx-quickstart on Sun Feb 13 23:54:25 2011.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Requests: HTTP for Humans
=========================

Release v\ |version|. (:ref:`Installation <install>`)

Requests is the only *Non-GMO* HTTP library for Python, safe for human
consumption.

**Warning:** Recreational use of other HTTP libraries may result in dangerous side-effects,
including: security vulnerabilities, verbose code, reinventing the wheel,
constantly reading documentation, depression, headaches, or even death.

Behold, the power of Requests::

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


Requests allows you to send *organic, grass-fed* HTTP/1.1 requests, without the
need for manual labor. There's no need to manually add query strings to your
URLs, or to form-encode your POST data. Keep-alive and HTTP connection pooling
are 100% automatic, powered by `urllib3 <https://github.com/shazow/urllib3>`_,
which is embedded within Requests.

User Testimonials
-----------------

Her Majesty's Government, Amazon, Google, Twilio, Runscope, Mozilla, Heroku,
PayPal, NPR, Obama for America, Transifex, Native Instruments, The Washington
Post, Twitter, SoundCloud, Kippt, Readability, Sony, and Federal U.S.
Institutions that prefer to be unnamed claim to use Requests internally.

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

Requests is one of the most downloaded Python packages of all time, pulling in
over 7,000,000 downloads every month. All the cool kids are doing it!

Supported Features
------------------

Requests is ready for today's web.

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
- HTTP(S) Proxy Support
- Connection Timeouts
- Streaming Downloads
- ``.netrc`` Support
- Chunked Requests
- Thread-safety

Requests supports Python 2.6 — 3.5, and runs great on PyPy.


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
   :maxdepth: 1

   community/faq
   community/recommended
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
