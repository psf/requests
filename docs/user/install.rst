.. _install:

Installation of Requests
========================

This part of the documentation covers the installation of Requests.
The first step to using any software package is getting it properly installed.


$ python -m pip install requests
--------------------------------

To install Requests, simply run this simple command in your terminal of choice::

    $ python -m pip install requests

Get the Source Code
-------------------

Requests is actively developed on GitHub, where the code is
`always available <https://github.com/psf/requests>`_.

You can either clone the public repository::

    $ git clone https://github.com/psf/requests.git

Or, download the `tarball <https://github.com/psf/requests/tarball/main>`_::

    $ curl -OL https://github.com/psf/requests/tarball/main
    # optionally, zipball is also available (for Windows users).

Once you have a copy of the source, you can embed it in your own Python
package, or install it into your site-packages easily::

    $ cd requests
    $ python -m pip install .
