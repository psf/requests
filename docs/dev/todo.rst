How to Help
===========

Requests is under active development, and contributions are more than welcome!

#. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug.
   There is a Contributor Friendly tag for issues that should be ideal for people who are not very
   familiar with the codebase yet.
#. Fork `the repository <https://github.com/kennethreitz/requests>`_ on Github to start making your
   changes to the **master** branch (or branch off of it).
#. Write a test which shows that the bug was fixed or that the feature works as expected.
#. Send a pull request and bug the maintainer until it gets merged and published. :)
   Make sure to add yourself to `AUTHORS <https://github.com/kennethreitz/requests/blob/master/AUTHORS.rst>`_.

Development dependencies
------------------------

You'll need to install py.test in order to run the Requests' test suite::

    $ make test-deps
    $ make test
    py.test
    platform darwin -- Python 2.7.3 -- pytest-2.3.4
    collected 25 items

    test_requests.py .........................
    25 passed in 3.50 seconds

Versions of Python
------------------

Officially (as of 26-Nov-2012), requests supports python 2.6-3.3. In the
future, support for 3.1 and 3.2 may be dropped. In general you will need to
test on at least one python 2 and one python 3 version. You can also set up
Travis CI for your own fork before you submit a pull request so that you are
assured your fork works. To use Travis CI for your fork and other projects see
their `documentation <http://about.travis-ci.org/docs/user/getting-started/>`_.

What Needs to be Done
---------------------

- Documentation needs a roadmap.
