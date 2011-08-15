.. _quickstart:

Quickstart
==========

.. module:: requests

Eager to get started? This page gives a good introduction in how to get started with Requests. This assumes you already have Tablib installed. If you do not, head over to the :ref:`Installation <install>` section.

First, make sure that:

* Tablib is :ref:`installed <install>`
* Tablib is :ref:`up-to-date <updates>`


Lets gets started with some simple use cases and examples.


Make a GET Request
------------------

Making a standard request with Requests is very simple.

Let's get GitHub's public timeline ::

    r = requests.get('https://github.com/timeline.json')

Now, we have a :class:`Response` object. We can get all the information
we need from this.


Response Content
----------------

We can read the content of the server's response::

    >>> r.content
    '[{"repository":{"open_issues":0,"url":"https://github.com/...



Response Status Codes
---------------------

We can check the response status code::

    >>> r.status_code
    200

Requests also comes with a built-in status code lookup object for easy
reference::

    >>> r.status_code == requests.codes.ok
    True