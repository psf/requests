.. Requests documentation master file, created by
   sphinx-quickstart on Sun Feb 13 23:54:25 2011.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Requests: Python HTTP (That Doesn't Suck)!
==========================================

Release |version|.

Requests is an :ref:`ISC Licensed <usc>` HTTP library, written in Python.

Most existing Python modules for sending HTTP requests are insane. This one strives to focus on the 95% use case: Simply sending the requests.

GET, HEAD, PUT, POST, DELETE.


How Simple?
-----------


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

