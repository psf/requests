Development Philosophy
======================

Requests is an open but opinionated library, created by an open but opinionated developer.


Benevolent Dictator
~~~~~~~~~~~~~~~~~~~

`Kenneth Reitz <http://kennethreitz.org>`_ is the BDFL. He has final say in any decision related to Requests.

Values
~~~~~~

- Simplicity is always better than functionality.
- Listen to everyone, then disregard it.
- The API is all that matters. Everything else is secondary.
- Fit the 90% use-case. Ignore the nay-sayers.

Semantic Versioning
~~~~~~~~~~~~~~~~~~~

For many years, the open source community has been plagued with version number dystonia. Numbers vary so greatly from project to project, they are practically meaningless.

Requests uses `Semantic Versioning <http://semver.org>`_. This specification seeks to put an end to this madness with a small set of practical guidelines for you and your colleagues to use in your next project.

Standard Library?
~~~~~~~~~~~~~~~~~

Requests has no *active* plans to be included in the standard library. This decision has been discussed at length with Guido as well as numerous core developers.

Essentially, the standard library is where a library goes to die. It is appropriate for a module to be included when active development is no longer necessary.

Requests just reached v1.0.0. This huge milestone marks a major step in the right direction.

Linux Distro Packages
~~~~~~~~~~~~~~~~~~~~~

Distributions have been made for many Linux repositories, including: Ubuntu, Debian, RHEL, and Arch.

These distributions are sometimes divergent forks, or are otherwise not kept up-to-date with the latest code and bugfixes. PyPI (and its mirrors) and GitHub are the official distribution sources; alternatives are not supported by the Requests project.
