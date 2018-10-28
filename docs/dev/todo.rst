How to Help
===========

.. image:: https://farm5.staticflickr.com/4290/34450900104_bc1d424213_k_d.jpg

Requests is under active development, and contributions are more than welcome!

#. Check for open issues or open a fresh issue to start a discussion around a bug.
   There is a Contributor Friendly tag for issues that should be ideal for people who are not very
   familiar with the codebase yet.
#. Fork `the repository <https://github.com/requests/requests>`_ on GitHub and start making your
   changes to a new branch.
#. Write a test which shows that the bug was fixed.
#. Send a pull request and bug the maintainer until it gets merged and published. :)
   Make sure to add yourself to `AUTHORS <https://github.com/requests/requests/blob/master/AUTHORS.rst>`_.

Feature Freeze
--------------

As of v1.0.0, Requests has now entered a feature freeze. Requests for new
features and Pull Requests implementing those features will not be accepted.

Development Dependencies
------------------------

You'll need to install py.test in order to run the Requests' test suite::

    $ venv .venv
    $ source .venv/bin/activate

    $ make
    $ python setup.py test
    ============================= test session starts ==============================
    platform darwin -- Python 3.4.4, pytest-3.0.6, py-1.4.32, pluggy-0.4.0
    ...
    collected 445 items

    tests/test_hooks.py ...
    tests/test_lowlevel.py ............
    tests/test_requests.py ...........................................................
    tests/test_structures.py ....................
    tests/test_testserver.py ...........
    tests/test_utils.py ..s...........................................................

    ============== 442 passed, 1 skipped, 2 xpassed in 46.48 seconds ===============

You can also run ``$ make tests`` to run against all supported Python versions, using tox/detox.

Runtime Environments
--------------------

Requests currently supports the following versions of Python:

- Python 2.7
- Python 3.4
- Python 3.5
- Python 3.6
- Python 3.7
- PyPy

Google AppEngine is not officially supported although support is available
with the `Requests-Toolbelt`_.

.. _Requests-Toolbelt: https://toolbelt.readthedocs.io/
