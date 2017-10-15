Release Process and Rules
=========================

.. image:: https://farm5.staticflickr.com/4215/34450901614_b74ae720db_k_d.jpg

.. versionadded:: v2.6.2

Starting with the version to be released after ``v2.6.2``, the following rules
will govern and describe how the Requests core team produces a new release.

Major Releases
--------------

A major release will include breaking changes. When it is versioned, it will
be versioned as ``vX.0.0``. For example, if the previous release was
``v10.2.7`` the next version will be ``v11.0.0``.

Breaking changes are changes that break backwards compatibility with prior
versions. If the project were to change the ``text`` attribute on a
``Response`` object to a method, that would only happen in a Major release.

Major releases may also include miscellaneous bug fixes and upgrades to
vendored packages. The core developers of Requests are committed to providing
a good user experience. This means we're also committed to preserving
backwards compatibility as much as possible. Major releases will be infrequent
and will need strong justifications before they are considered.

Minor Releases
--------------

A minor release will not include breaking changes but may include
miscellaneous bug fixes and upgrades to vendored packages. If the previous
version of Requests released was ``v10.2.7`` a minor release would be
versioned as ``v10.3.0``.

Minor releases will be backwards compatible with releases that have the same
major version number. In other words, all versions that would start with
``v10.`` should be compatible with each other.

Hotfix Releases
---------------

A hotfix release will only include bug fixes that were missed when the project
released the previous version. If the previous version of Requests released
``v10.2.7`` the hotfix release would be versioned as ``v10.2.8``.

Hotfixes will **not** include upgrades to vendored dependencies after
``v2.6.2``

Reasoning
---------

In the 2.5 and 2.6 release series, the Requests core team upgraded vendored
dependencies and caused a great deal of headaches for both users and the core
team. To reduce this pain, we're forming a concrete set of procedures so
expectations will be properly set.
