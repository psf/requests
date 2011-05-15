.. Requests documentation master file, created by
   sphinx-quickstart on Sun Feb 13 23:54:25 2011.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Requests: HTTP for Humans
=========================

Release |version|.

Requests is an :ref:`ISC Licensed <isc>` HTTP library, written in Python, for human beings.

Most existing Python modules for sending HTTP requests are extremely verbose and cumbersome. Python's builtin :py:class:`urllib2` module provides all the HTTP capabilities required, but the api is thoroughly **broken**. It reqires an *enormous* amount of work (even method overrides) to perform the simplest of tasks.

Enter Requests. Requests allow you to send **GET**, **HEAD**, **PUT**, **POST**, and **DELETE** HTTP requests. You can add headers, form data, miltipart files, and parameters with simple Python dictionaries, and access the response data in the same way. It's powered by :py:class:`urllib2`, but it does all the hard work and crazy hacks for you.


It's Simple
-----------

How Simple?


requests
~~~~~~~~

::

    >>> import requests
    >>> r = requests.get('https://convore.com/api', auth=('username', 'password'))
    >>> r.headers['content-encoding']
    json


urllib2
~~~~~~~

::

    # complicated.


I recommend you start with :ref:`Installation <install>`.






Contents:

.. toctree::
   :maxdepth: 2

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

