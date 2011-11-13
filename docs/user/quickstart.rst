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

Requests does its best to decode content from the server. Most unicode
charsets, ``gzip``, and ``deflate`` encodings are all seamlessly decoded.


Make a POST Request
-------------------

POST requests are equally simple::

    r = requests.post("http://httpbin.org/post")


Typically, you want to send some form-encoded data — much like an HTML form.
To do this, simply pass a dictionary to the `data` argument. Your
dictionary of data will automatically be form-encoded when the request is made::

    >>> payload = {'key1': 'value1', 'key2': 'value2'}
    >>> r = requests.post("http://httpbin.org/post", data=payload)
    >>> print r.content
    {
      "origin": "179.13.100.4",
      "files": {},
      "form": {
        "key2": "value2",
        "key1": "value1"
      },
      "url": "http://httpbin.org/post",
      "args": {},
      "headers": {
        "Content-Length": "23",
        "Accept-Encoding": "identity, deflate, compress, gzip",
        "Accept": "*/*",
        "User-Agent": "python-requests/0.8.0",
        "Host": "127.0.0.1:7077",
        "Content-Type": "application/x-www-form-urlencoded"
      },
      "data": ""
    }

There are many times that you want to send data that is not form-encoded. If you pass in a ``string`` instead of a ``dict``, that data will be posted directly.

For example, the GitHub API v3 accepts JSON-Encoded POST/PATCH data::

    url = 'https://api.github.com/some/endpoint'
    payload = {'some': 'data'}

    r = requests.post(url, data=json.dumps(payload))


Custom Headers
--------------

If you'd like to add HTTP headers to a request, simply pass in a ``dict`` to the
``headers`` parameter.

For example, we didn't specify our content-type in the previous example::

    url = 'https://api.github.com/some/endpoint'
    payload = {'some': 'data'}
    headers = {'content-type': 'application/json'}

    r = requests.post(url, data=json.dumps(payload), headers=headers)


POST a Multipart-Encoded File
-----------------------------

Requests makes it simple to upload Multipart-encoded files::

    >>> url = 'http://httpbin.org/post'
    >>> files = {'report.xls': open('report.xls', 'rb')}

    >>> r = requests.post(url, files=files)
    >>> r.content
    {
      "origin": "179.13.100.4",
      "files": {
        "report.xls": "<censored...binary...data>"
      },
      "form": {},
      "url": "http://httpbin.org/post",
      "args": {},
      "headers": {
        "Content-Length": "3196",
        "Accept-Encoding": "identity, deflate, compress, gzip",
        "Accept": "*/*",
        "User-Agent": "python-requests/0.8.0",
        "Host": "httpbin.org:80",
        "Content-Type": "multipart/form-data; boundary=127.0.0.1.502.21746.1321131593.786.1"
      },
      "data": ""
    }



Response Status Codes
---------------------

We can check the response status code::

    >>> r.status_code
    200

Requests also comes with a built-in status code lookup object for easy
reference::

    >>> r.status_code == requests.codes.ok
    True

If we made a bad request (non-200 response), we can raise it with
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
authentication, but the most common is HTTP Basic Auth.

Making requests with Basic Auth is extremely simple::

    >>> requests.get('https://api.github.com/user', auth=('user', 'pass'))
    <Response [200]>


Digest Authentication
---------------------

Another popular form of web service protection is Digest Authentication::

    >>> url = 'http://httpbin.org/digest-auth/auth/user/pass'
    >>> requests.get(url, auth=('digest', 'user', 'pass'))
    <Response [200]>


Redirection and History
-----------------------

Requests will automatically perform location redirection while using impodotent methods.

GitHub redirects all HTTP requests to HTTPS. Let's see what happens::

    >>> r = requests.get('http://github.com')
    >>> r.url
    'https://github.com/'
    >>> r.status_code
    200
    >>> r.history
    [<Response [301]>]

The :class:`Response.history` list contains a list of the
:class:`Request` objects that were created in order to complete the request.

If you're using GET, HEAD, or OPTIONS, you can disable redirection
handling with the ``disable_redirects`` parameter::

    >>> r = requests.get('http://github.com')
    >>> r.status_code
    301
    >>> r.history
    []

If you're using POST, PUT, PATCH, *&c*, you can also explicitly enable redirection as well::

    >>> r = requests.post('http://github.com', allow_redirects=True)
    >>> r.url
    'https://github.com/'
    >>> r.history
    [<Response [301]>]


Timeouts
--------

You can tell requests to stop waiting for a response after a given number of seconds with the ``timeout`` parameter::

    >>> requests.get('http://github.com', timeout=0.001)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
    requests.exceptions.Timeout: Request timed out.

.. admonition:: Note

    ``timeout`` only effects the connection process itself, not the downloading of the respone body.


Errors and Exceptions
---------------------

In the event of a network problem (e.g. DNS failure, refused connection, etc),
Requests will raise a :class:`ConnectionError` exception.

In the event of the rare invalid HTTP response, Requests will raise
an  :class:`HTTPError` exception.

If a request times out, a :class:`Timeout` exception is raised.

If a request exceeds the configured number of maximum redirections, a :class:`TooManyRedirects` exception is raised.

All exceptions that Requests explicitly raises inherit from
:class:`requests.exceptions.RequestException`.

-----------------------

Ready for more? Check out the :ref:`advanced <advanced>` section.
