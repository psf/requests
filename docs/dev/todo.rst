How to Help
===========

Requests is under active development, and contributions are more than welcome!

#. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug.
   There is a Contributor Friendly tag for issues that should be ideal for people who are not very
   familiar with the codebase yet.
#. Fork `the repository <https://github.com/kennethreitz/requests>`_ on Github to start making your
   changes to the **develop** branch (or branch off of it).
#. Write a test which shows that the bug was fixed or that the feature works as expected.
#. Send a pull request and bug the maintainer until it gets merged and published. :)
   Make sure to add yourself to `AUTHORS <https://github.com/kennethreitz/requests/blob/develop/AUTHORS.rst>`_.

Development dependencies
------------------------

You'll need to install ``gunicorn`` and ``httpbin`` and various other dependencies in
order to run requests' test suite::

    $ virtualenv env
    $ . env/bin/activate
    $ make
    $ make test

The ``Makefile`` has various useful targets for testing.

What Needs to be Done
---------------------

- Documentation needs a roadmap.
