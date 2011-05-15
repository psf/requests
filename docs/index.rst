.. Requests documentation master file, created by
   sphinx-quickstart on Sun Feb 13 23:54:25 2011.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Requests: Python HTTP (That Doesn't Suck)!
==========================================

Release |version|.

Requests is an :ref:`ISC Licensed <isc>` HTTP library, written in Python.

Most existing Python modules for sending HTTP requests are extremely verbose and cumbersome. Python's builtin :py:class:`urllib2` module provides all the HTTP functionality I need, but it's api is **broken**. It reqires an enormous amount of work (even method ovrrides) to do the simplet of things. So, I decided to wrap it and make it super simple.

Requests allow you to send GET, HEAD, PUT, POST, DELETE requests. You can add headers, form data, miltipart files, and parameters with simple Python dictionaries.


It's Simple
-----------

How Simple?


requests
~~~~~~~~

::

    import requests
    requests.get('https://convore.com/api', auth=('username', 'password'))


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

