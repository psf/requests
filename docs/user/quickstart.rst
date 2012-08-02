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


Let's get started with some simple examples.


Make a Request
------------------

Making a request with Requests is very simple.

Begin by importing the Requests module::
    
    >>> import requests

Now, let's try to get a webpage. For this example, let's get GitHub's public
timeline ::

    >>> r = requests.get('https://github.com/timeline.json')

Now, we have a :class:`Response` object called ``r``. We can get all the
information we need from this object.

Requests' simple API means that all forms of HTTP request are as obvious. For
example, this is how you make an HTTP POST request::
    
    >>> r = requests.post("http://httpbin.org/post")

Nice, right? What about the other HTTP request types: PUT, DELETE, HEAD and
OPTIONS? These are all just as simple::
    
    >>> r = requests.put("http://httpbin.org/put")
    >>> r = requests.delete("http://httpbin.org/delete")
    >>> r = requests.head("http://httpbin.org/get")
    >>> r = requests.options("http://httpbin.org/get")

That's all well and good, but it's also only the start of what Requests can
do.


Passing Parameters In URLs
--------------------------

You often want to send some sort of data in the URL's query string. If
you were constructing the URL by hand, this data would be given as key/value
pairs in the URL after a question mark, e.g. ``httpbin.org/get?key=val``.
Requests allows you to provide these arguments as a dictionary, using the
``params`` keyword argument. As an example, if you wanted to pass
``key1=value1`` and ``key2=value2`` to ``httpbin.org/get``, you would use the
following code::

    >>> payload = {'key1': 'value1', 'key2': 'value2'}
    >>> r = requests.get("http://httpbin.org/get", params=payload)

You can see that the URL has been correctly encoded by printing the URL::

    >>> print r.url
    u'http://httpbin.org/get?key2=value2&key1=value1'
    

Response Content
----------------

We can read the content of the server's response. Consider the GitHub timeline
again::

    >>> import requests
    >>> r = requests.get('https://github.com/timeline.json')
    >>> r.text
    '[{"repository":{"open_issues":0,"url":"https://github.com/...

Requests will automatically decode content from the server. Most unicode
charsets are seamlessly decoded.

When you make a request, ``r.encoding`` is set, based on the HTTP headers.
Requests will use that encoding when you access ``r.text``.  If ``r.encoding``
is ``None``, Requests will make an extremely educated guess of the encoding
of the response body. You can manually set ``r.encoding`` to any encoding
you'd like, and that charset will be used.


Binary Response Content
-----------------------

You can also access the response body as bytes, for non-text requests::

    >>> r.content
    b'[{"repository":{"open_issues":0,"url":"https://github.com/...

The ``gzip`` and ``deflate`` transfer-encodings are automatically decoded for you.

For example, to create an image from binary data returned by a request, you can
use the following code:

    >>> from PIL import Image
    >>> from StringIO import StringIO
    >>> i = Image.open(StringIO(r.content))


JSON Response Content
---------------------

There's also a builtin JSON decoder, in case you're dealing with JSON data::

    >>> import requests
    >>> r = requests.get('https://github.com/timeline.json')
    >>> r.json
    [{u'repository': {u'open_issues': 0, u'url': 'https://github.com/...

In case the JSON decoding fails, ``r.json`` simply returns ``None``.


Raw Response Content
--------------------

In the rare case that you'd like to get the absolute raw socket response from the server,
you can access ``r.raw``::

    >>> r.raw
    <requests.packages.urllib3.response.HTTPResponse object at 0x101194810>

    >>> r.raw.read(10)
    '\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03'


Custom Headers
--------------

If you'd like to add HTTP headers to a request, simply pass in a ``dict`` to the
``headers`` parameter.

For example, we didn't specify our content-type in the previous example::

    >>> import json
    >>> url = 'https://api.github.com/some/endpoint'
    >>> payload = {'some': 'data'}
    >>> headers = {'content-type': 'application/json'}

    >>> r = requests.post(url, data=json.dumps(payload), headers=headers)


More complicated POST requests
------------------------------

Typically, you want to send some form-encoded data — much like an HTML form.
To do this, simply pass a dictionary to the `data` argument. Your
dictionary of data will automatically be form-encoded when the request is made::

    >>> payload = {'key1': 'value1', 'key2': 'value2'}
    >>> r = requests.post("http://httpbin.org/post", data=payload)
    >>> print r.text
    {
      // ...snip... //
      "form": {
        "key2": "value2",
        "key1": "value1"
      },
      // ...snip... //
    }

There are many times that you want to send data that is not form-encoded. If you pass in a ``string`` instead of a ``dict``, that data will be posted directly.

For example, the GitHub API v3 accepts JSON-Encoded POST/PATCH data::

    >>> import json
    >>> url = 'https://api.github.com/some/endpoint'
    >>> payload = {'some': 'data'}

    >>> r = requests.post(url, data=json.dumps(payload))


POST a Multipart-Encoded File
-----------------------------

Requests makes it simple to upload Multipart-encoded files::

    >>> url = 'http://httpbin.org/post'
    >>> files = {'file': open('report.xls', 'rb')}

    >>> r = requests.post(url, files=files)
    >>> r.text
    {
      // ...snip... //
      "files": {
        "file": "<censored...binary...data>"
      },
      // ...snip... //
    }

You can set the filename explicitly::

    >>> url = 'http://httpbin.org/post'
    >>> files = {'file': ('report.xls', open('report.xls', 'rb'))}

    >>> r = requests.post(url, files=files)
    >>> r.text
    {
      // ...snip... //
      "files": {
        "file": "<censored...binary...data>"
      },
      // ...snip... //
    }

If you want, you can send strings to be received as files::

    >>> url = 'http://httpbin.org/post'
    >>> files = {'file': ('report.csv', 'some,data,to,send\nanother,row,to,send\n')} 

    >>> r = requests.post(url, files=files)
    >>> r.text
    {
      // ...snip... //
      "files": {
        "file": "some,data,to,send\\nanother,row,to,send\\n"
      },
      // ...snip... //
    }


Response Status Codes
---------------------

We can check the response status code::

    >>> r = requests.get('http://httpbin.org/get')
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
      File "requests/models.py", line 832, in raise_for_status
        raise http_error
    requests.exceptions.HTTPError: 404 Client Error

But, since our ``status_code`` for ``r`` was ``200``, when we call
``raise_for_status()`` we get::

    >>> r.raise_for_status()
    None

All is well.


Response Headers
----------------

We can view the server's response headers using a Python dictionary::

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

    >>> r.cookies['requests-is']
    'awesome'

To send your own cookies to the server, you can use the ``cookies``
parameter::

    >>> url = 'http://httpbin.org/cookies'
    >>> cookies = dict(cookies_are='working')

    >>> r = requests.get(url, cookies=cookies)
    >>> r.text
    '{"cookies": {"cookies_are": "working"}}'


Basic Authentication
--------------------

Many web services require authentication. There many different types of
authentication, but the most common is HTTP Basic Auth.

Making requests with Basic Auth is extremely simple::

    >>> from requests.auth import HTTPBasicAuth
    >>> requests.get('https://api.github.com/user', auth=HTTPBasicAuth('user', 'pass'))
    <Response [200]>

Due to the prevalence of HTTP Basic Auth, requests provides a shorthand for
this authentication method::

    >>> requests.get('https://api.github.com/user', auth=('user', 'pass'))
    <Response [200]>

Providing the credentials as a tuple in this fashion is functionally equivalent
to the ``HTTPBasicAuth`` example above.


Digest Authentication
---------------------

Another popular form of web service protection is Digest Authentication::

    >>> from requests.auth import HTTPDigestAuth
    >>> url = 'http://httpbin.org/digest-auth/auth/user/pass'
    >>> requests.get(url, auth=HTTPDigestAuth('user', 'pass'))
    <Response [200]>


OAuth Authentication
--------------------

Miguel Araujo's `requests-oauth <http://pypi.python.org/pypi/requests-oauth>`_
project provides a simple interface for establishing OAuth connections.
Documentation and examples can be found on the requests-oauth
`git repository <https://github.com/maraujop/requests-oauth>`_.


Redirection and History
-----------------------

Requests will automatically perform location redirection while using the GET
and OPTIONS verbs.

GitHub redirects all HTTP requests to HTTPS. We can use the ``history`` method
of the Response object to track redirection. Let's see what Github does::

    >>> r = requests.get('http://github.com')
    >>> r.url
    'https://github.com/'
    >>> r.status_code
    200
    >>> r.history
    [<Response [301]>]

The :class:`Response.history` list contains a list of the
:class:`Request` objects that were created in order to complete the request. The list is sorted from the oldest to the most recent request.

If you're using GET or OPTIONS, you can disable redirection handling with the
``allow_redirects`` parameter::

    >>> r = requests.get('http://github.com', allow_redirects=False)
    >>> r.status_code
    301
    >>> r.history
    []

If you're using POST, PUT, PATCH, DELETE or HEAD, you can enable
redirection as well::

    >>> r = requests.post('http://github.com', allow_redirects=True)
    >>> r.url
    'https://github.com/'
    >>> r.history
    [<Response [301]>]


Timeouts
--------

You can tell requests to stop waiting for a response after a given number of
seconds with the ``timeout`` parameter::

    >>> requests.get('http://github.com', timeout=0.001)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
    requests.exceptions.Timeout: Request timed out.

.. admonition:: Note:

    ``timeout`` only effects the connection process itself, not the
    downloading of the response body.


Errors and Exceptions
---------------------

In the event of a network problem (e.g. DNS failure, refused connection, etc),
Requests will raise a :class:`ConnectionError` exception.

In the event of the rare invalid HTTP response, Requests will raise
an  :class:`HTTPError` exception.

If a request times out, a :class:`Timeout` exception is raised.

If a request exceeds the configured number of maximum redirections, a
:class:`TooManyRedirects` exception is raised.

All exceptions that Requests explicitly raises inherit from
:class:`requests.exceptions.RequestException`.

You can refer to :ref:`Configuration API Docs <configurations>` for immediate
raising of :class:`HTTPError` exceptions via the ``danger_mode`` option or
have Requests catch the majority of
:class:`requests.exceptions.RequestException` exceptions with the ``safe_mode``
option.

-----------------------

Ready for more? Check out the :ref:`advanced <advanced>` section.
