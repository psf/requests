.. _quickstart:

Quickstart
==========

.. module:: requests.models

Eager to get started? This page gives a good introduction in how to get started
with Requests. This assumes you already have Requests installed. If you do not,
head over to the :ref:`Installation <install>` section.

First, make sure that:

* Requests is :ref:`installed <install>`
* Requests is :ref:`up-to-date <updates>`


Lets gets started with some simple use cases and examples.


Make a GET Request
------------------

Making a standard request with Requests is very simple.

Let's get GitHub's public timeline ::

    r = requests.get('https://github.com/timeline.json')

Now, we have a :class:`Response` object called ``r``. We can get all the
information we need from this.


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

But, since our ``status_code`` was ``200``, when we call it::

    >>> r.raise_for_status()
    None

All is well.


Response Headers
----------------

We can view the server's response headers with a simple Python dictionary
interface::

    >>> r.headers
    {
        'status': '200 OK',
        'content-encoding': 'gzip',
        'transfer-encoding': 'chunked',
        'connection': 'close',
        'server': 'nginx/1.0.4',
        'x-runtime': '148ms',
        'etag': '"e1ca502697e5c9317743dc078f67693f"',
        'content-type': 'application/json; charset=utf-8'
    }

The dictionary is special, though: it's made just for HTTP headers. According to
`RFC 2616 <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html>`_, HTTP
Headers are case-insensitive.

So, we can access the headers using any capitalization we want::

    >>> r.headers['Content-Type']
    'application/json; charset=utf-8'

    >>> r.headers.get('content-type')
    'application/json; charset=utf-8'

If a header doesn't exist in the Response, its value defaults to ``None``::

    >>> r.headers['X-Random']
    None


Cookies
-------

If a response contains some Cookies, you can get quick access to them::

    >>> url = 'http://httpbin.org/cookies/set/requests-is/awesome'
    >>> r = requests.get(url)

    >>> print r.cookies
    {'requests-is': 'awesome'}

The underlying CookieJar is also available for more advanced handling::

    >>> r.request.cookiejar
    <cookielib.CookieJar>

To send your own cookies to the server, you can use the ``cookies``
parameter::

    >>> url = 'http://httpbin.org/cookies'
    >>> cookies = dict(cookies_are='working')

    >>> r = requests.get(url, cookies=cookies)
    >>> r.content
    '{"cookies": {"cookies_are": "working"}}'


Basic Authentication
--------------------

Most web services require authentication. There many different types of
authentication, but the most common is called HTTP Basic Auth.

Making requests with Basic Auth is easy, with Requests::

    >>> requests.get('https://api.github.com/user', auth=('user', 'pass'))
    <Response [200]>


Digest Authentication
---------------------

Another popular form of protecting web service is Digest Authentication.

Requests supports it!::

    >>> url = 'http://httpbin.org/digest-auth/auth/user/pass'
    >>> requests.get(url, auth=('digest', 'user', 'pass'))
    <Response [200]>


-----------------------

Ready for more? Check out the :ref:`advanced <advanced>` section.
