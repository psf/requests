Development Philosophy
======================

.. image:: https://farm5.staticflickr.com/4231/34484831073_636008a23d_k_d.jpg

Requests is an open but opinionated library, created by an open but opinionated developer.


Management Style
~~~~~~~~~~~~~~~~

`Kenneth Reitz <https://www.kennethreitz.org/>`_ is the BDFL. He has final say in any decision related to the Requests project. Kenneth is responsible for the direction and form of the library, as well as its presentation. In addition to making decisions based on technical merit, he is responsible for making decisions based on the development philosophy of Requests.

`Ian Cordasco <http://www.coglib.com/~icordasc/>`_, `Cory Benfield <https://lukasa.co.uk/about/>`_, and `Nate Prewitt <https://www.nateprewitt.com/>`_ are the core contributors. They are responsible for triaging bug reports, reviewing pull requests and ensuring that Kenneth is kept up to speed with developments around the library. The day-to-day managing of the project is done by the core contributors. They are responsible for making judgements about whether or not a feature request is likely to be accepted by Kenneth. Their word is, in some ways, more final than Kenneth's.

Values
~~~~~~

- Simplicity is always better than functionality.
- Listen to everyone, then disregard it.
- The API is all that matters. Everything else is secondary.
- Fit the 90% use-case. Ignore the nay-sayers.

Semantic Versioning
~~~~~~~~~~~~~~~~~~~

For many years, the open source community has been plagued with version number dystonia. Numbers vary so greatly from project to project, they are practically meaningless.

Requests uses `Semantic Versioning <https://semver.org/>`_. This specification seeks to put an end to this madness with a small set of practical guidelines for you and your colleagues to use in your next project.

Standard Library?
~~~~~~~~~~~~~~~~~

Requests has no *active* plans to be included in the standard library. This decision has been discussed at length with Guido as well as numerous core developers.

.. raw:: html

    <script async class="speakerdeck-embed" data-id="68f22f0841734d848315c618111b13ea" data-ratio="1.33333333333333" src="//speakerdeck.com/assets/embed.js"></script>

Essentially, the standard library is where a library goes to die. It is appropriate for a module to be included when active development is no longer necessary.

Linux Distro Packages
~~~~~~~~~~~~~~~~~~~~~

Distributions have been made for many Linux repositories, including: Ubuntu, Debian, RHEL, and Arch.

These distributions are sometimes divergent forks, or are otherwise not kept up-to-date with the latest code and bugfixes. PyPI (and its mirrors) and GitHub are the official distribution sources; alternatives are not supported by the Requests project.
