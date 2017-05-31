.. _install:

Installation of Requests
========================

This part of the documentation covers the installation of Requests.
The first step to using any software package is getting it properly installed.


$ pip install requests
----------------------

To install Requests, simply run this simple command in your terminal of choice::

    $ pip install requests

If you don't have `pip <https://pip.pypa.io>`_ installed (tisk tisk!),
`this Python installation guide <http://docs.python-guide.org/en/latest/starting/installation/>`_
can guide you through the process.

Get the Source Code
-------------------

Requests is actively developed on GitHub, where the code is
`always available <https://github.com/requests/requests>`_.

You can either clone the public repository::

    $ git clone git://github.com/requests/requests.git

Or, download the `tarball <https://github.com/requests/requests/tarball/master>`_::

    $ curl -OL https://github.com/requests/requests/tarball/master
    # optionally, zipball is also available (for Windows users).

Once you have a copy of the source, you can embed it in your own Python
package, or install it into your site-packages easily::

    $ cd requests
    $ pip install .
