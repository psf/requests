.. _install:

Installation
============

This part of the documentation covers the installation of Requests.
The first step to using any software package is getting it properly installed.


Distribute & Pip
----------------

Installing Requests is simple with `pip <http://www.pip-installer.org/>`_::

    $ pip install requests

or, with `easy_install <http://pypi.python.org/pypi/setuptools>`_::

    $ easy_install requests

But, you really `shouldn't do that <http://www.pip-installer.org/en/latest/other-tools.html#pip-compared-to-easy-install>`_.



Cheeseshop (PyPI) Mirror
------------------------

If the Cheeseshop (a.k.a. PyPI) is down, you can also install Requests from one
of the mirrors. `Crate.io <http://crate.io>`_ is one of them::

    $ pip install -i http://simple.crate.io/ requests


Get the Code
------------

Requests is actively developed on GitHub, where the code is
`always available <https://github.com/kennethreitz/requests>`_.

You can either clone the public repository::

    git clone git://github.com/kennethreitz/requests.git

Download the `tarball <https://github.com/kennethreitz/requests/tarball/master>`_::

    $ curl -OL https://github.com/kennethreitz/requests/tarball/master

Or, download the `zipball <https://github.com/kennethreitz/requests/zipball/master>`_::

    $ curl -OL https://github.com/kennethreitz/requests/zipball/master


Once you have a copy of the source, you can embed it in your Python package,
or install it into your site-packages easily::

    $ python setup.py install
