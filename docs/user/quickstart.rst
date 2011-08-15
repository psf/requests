.. _quickstart:

Quickstart
==========

.. module:: requests.models

Eager to get started? This page gives a good introduction in how to get started with Requests. This assumes you already have Requests installed. If you do not, head over to the :ref:`Installation <install>` section.

First, make sure that:

* Tablib is :ref:`installed <install>`
* Tablib is :ref:`up-to-date <updates>`


Lets gets started with some simple use cases and examples.


Make a GET Request
------------------

Making a standard request with Requests is very simple.

Let's get GitHub's public timeline ::

    r = requests.get('https://github.com/timeline.json')

Now, we have a :class:`Response` object called ``r``. We can get all the information we need from this.


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

If we made a bad request, we can raise it with
:class:`Response.raise_for_status()`::

    >>> _r = requests.get('http://httpbin.org/status/404')
    >>> _r.status_code
    404

    >>> _r.raise_for_status()
    Traceback (most recent call last):
      File "requests/models.py", line 394, in raise_for_status
        raise self.error
    urllib2.HTTPError: HTTP Error 404: NOT FOUND

But, sice our ``status_code`` was ``200``, when we call it::

    >>> r.raise_for_status()
    None

All is well.