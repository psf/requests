.. _advanced:

Advanced Usage
==============

.. image:: https://farm5.staticflickr.com/4263/35163665790_d182d84f5e_k_d.jpg

This document covers some of Requests more advanced features.

.. _session-objects:

Session Objects
---------------

The Session object allows you to persist certain parameters across
requests. It also persists cookies across all requests made from the
Session instance, and will use ``urllib3``'s `connection pooling`_. So if
you're making several requests to the same host, the underlying TCP
connection will be reused, which can result in a significant performance
increase (see `HTTP persistent connection`_).

A Session object has all the methods of the main Requests API.

Let's persist some cookies across requests::

    s = requests.Session()

    s.get('https://httpbin.org/cookies/set/sessioncookie/123456789')
    r = s.get('https://httpbin.org/cookies')

    print(r.text)
    # '{"cookies": {"sessioncookie": "123456789"}}'


Sessions can also be used to provide default data to the request methods. This
is done by providing data to the properties on a Session object::

    s = requests.Session()
    s.auth = ('user', 'pass')
    s.headers.update({'x-test': 'true'})

    # both 'x-test' and 'x-test2' are sent
    s.get('https://httpbin.org/headers', headers={'x-test2': 'true'})


Any dictionaries that you pass to a request method will be merged with the
session-level values that are set. The method-level parameters override session
parameters.

Note, however, that method-level parameters will *not* be persisted across
requests, even if using a session. This example will only send the cookies
with the first request, but not the second::

    s = requests.Session()

    r = s.get('https://httpbin.org/cookies', cookies={'from-my': 'browser'})
    print(r.text)
    # '{"cookies": {"from-my": "browser"}}'

    r = s.get('https://httpbin.org/cookies')
    print(r.text)
    # '{"cookies": {}}'


If you want to manually add cookies to your session, use the
:ref:`Cookie utility functions <api-cookies>` to manipulate
:attr:`Session.cookies <requests.Session.cookies>`.

Sessions can also be used as context managers::

    with requests.Session() as s:
        s.get('https://httpbin.org/cookies/set/sessioncookie/123456789')

This will make sure the session is closed as soon as the ``with`` block is
exited, even if unhandled exceptions occurred.


.. admonition:: Remove a Value From a Dict Parameter

    Sometimes you'll want to omit session-level keys from a dict parameter. To
    do this, you simply set that key's value to ``None`` in the method-level
    parameter. It will automatically be omitted.

All values that are contained within a session are directly available to you.
See the :ref:`Session API Docs <sessionapi>` to learn more.

.. _request-and-response-objects:

Request and Response Objects
----------------------------

Whenever a call is made to ``requests.get()`` and friends, you are doing two
major things. First, you are constructing a ``Request`` object which will be
sent off to a server to request or query some resource. Second, a ``Response``
object is generated once Requests gets a response back from the server.
The ``Response`` object contains all of the information returned by the server and
also contains the ``Request`` object you created originally. Here is a simple
request to get some very important information from Wikipedia's servers::

    >>> r = requests.get('https://en.wikipedia.org/wiki/Monty_Python')

If we want to access the headers the server sent back to us, we do this::

    >>> r.headers
    {'content-length': '56170', 'x-content-type-options': 'nosniff', 'x-cache':
    'HIT from cp1006.eqiad.wmnet, MISS from cp1010.eqiad.wmnet', 'content-encoding':
    'gzip', 'age': '3080', 'content-language': 'en', 'vary': 'Accept-Encoding,Cookie',
    'server': 'Apache', 'last-modified': 'Wed, 13 Jun 2012 01:33:50 GMT',
    'connection': 'close', 'cache-control': 'private, s-maxage=0, max-age=0,
    must-revalidate', 'date': 'Thu, 14 Jun 2012 12:59:39 GMT', 'content-type':
    'text/html; charset=UTF-8', 'x-cache-lookup': 'HIT from cp1006.eqiad.wmnet:3128,
    MISS from cp1010.eqiad.wmnet:80'}

However, if we want to get the headers we sent the server, we simply access the
request, and then the request's headers::

    >>> r.request.headers
    {'Accept-Encoding': 'identity, deflate, compress, gzip',
    'Accept': '*/*', 'User-Agent': 'python-requests/1.2.0'}

.. _prepared-requests:

Prepared Requests
-----------------

Whenever you receive a :class:`Response <requests.Response>` object
from an API call or a Session call, the ``request`` attribute is actually the
``PreparedRequest`` that was used. In some cases you may wish to do some extra
work to the body or headers (or anything else really) before sending a
request. The simple recipe for this is the following::

    from requests import Request, Session

    s = Session()

    req = Request('POST', url, data=data, headers=headers)
    prepped = req.prepare()

    # do something with prepped.body
    prepped.body = 'No, I want exactly this as the body.'

    # do something with prepped.headers
    del prepped.headers['Content-Type']

    resp = s.send(prepped,
        stream=stream,
        verify=verify,
        proxies=proxies,
        cert=cert,
        timeout=timeout
    )

    print(resp.status_code)

Since you are not doing anything special with the ``Request`` object, you
prepare it immediately and modify the ``PreparedRequest`` object. You then
send that with the other parameters you would have sent to ``requests.*`` or
``Session.*``.

However, the above code will lose some of the advantages of having a Requests
:class:`Session <requests.Session>` object. In particular,
:class:`Session <requests.Session>`-level state such as cookies will
not get applied to your request. To get a
:class:`PreparedRequest <requests.PreparedRequest>` with that state
applied, replace the call to :meth:`Request.prepare()
<requests.Request.prepare>` with a call to
:meth:`Session.prepare_request() <requests.Session.prepare_request>`, like this::

    from requests import Request, Session

    s = Session()
    req = Request('GET',  url, data=data, headers=headers)

    prepped = s.prepare_request(req)

    # do something with prepped.body
    prepped.body = 'Seriously, send exactly these bytes.'

    # do something with prepped.headers
    prepped.headers['Keep-Dead'] = 'parrot'

    resp = s.send(prepped,
        stream=stream,
        verify=verify,
        proxies=proxies,
        cert=cert,
        timeout=timeout
    )

    print(resp.status_code)

When you are using the prepared request flow, keep in mind that it does not take into account the environment.
This can cause problems if you are using environment variables to change the behaviour of requests.
For example: Self-signed SSL certificates specified in ``REQUESTS_CA_BUNDLE`` will not be taken into account.
As a result an ``SSL: CERTIFICATE_VERIFY_FAILED`` is thrown.
You can get around this behaviour by explicity merging the environment settings into your session::

    from requests import Request, Session

    s = Session()
    req = Request('GET', url)

    prepped = s.prepare_request(req)

    # Merge environment settings into session
    settings = s.merge_environment_settings(prepped.url, None, None, None, None)
    resp = s.send(prepped, **settings)

    print(resp.status_code)

.. _verification:

SSL Cert Verification
---------------------

Requests verifies SSL certificates for HTTPS requests, just like a web browser.
By default, SSL verification is enabled, and Requests will throw a SSLError if
it's unable to verify the certificate::

    >>> requests.get('https://requestb.in')
    requests.exceptions.SSLError: hostname 'requestb.in' doesn't match either of '*.herokuapp.com', 'herokuapp.com'

I don't have SSL setup on this domain, so it throws an exception. Excellent. GitHub does though::

    >>> requests.get('https://github.com')
    <Response [200]>

You can pass ``verify`` the path to a CA_BUNDLE file or directory with certificates of trusted CAs::

    >>> requests.get('https://github.com', verify='/path/to/certfile')

or persistent::

    s = requests.Session()
    s.verify = '/path/to/certfile'

.. note:: If ``verify`` is set to a path to a directory, the directory must have been processed using
  the c_rehash utility supplied with OpenSSL.

This list of trusted CAs can also be specified through the ``REQUESTS_CA_BUNDLE`` environment variable.

Requests can also ignore verifying the SSL certificate if you set ``verify`` to False::

    >>> requests.get('https://kennethreitz.org', verify=False)
    <Response [200]>

By default, ``verify`` is set to True. Option ``verify`` only applies to host certs.

Client Side Certificates
------------------------

You can also specify a local cert to use as client side certificate, as a single
file (containing the private key and the certificate) or as a tuple of both
files' paths::

    >>> requests.get('https://kennethreitz.org', cert=('/path/client.cert', '/path/client.key'))
    <Response [200]>

or persistent::

    s = requests.Session()
    s.cert = '/path/client.cert'

If you specify a wrong path or an invalid cert, you'll get a SSLError::

    >>> requests.get('https://kennethreitz.org', cert='/wrong_path/client.pem')
    SSLError: [Errno 336265225] _ssl.c:347: error:140B0009:SSL routines:SSL_CTX_use_PrivateKey_file:PEM lib

.. warning:: The private key to your local certificate *must* be unencrypted.
   Currently, Requests does not support using encrypted keys.

.. _ca-certificates:

CA Certificates
---------------

Requests uses certificates from the package `certifi`_. This allows for users
to update their trusted certificates without changing the version of Requests.

Before version 2.16, Requests bundled a set of root CAs that it trusted,
sourced from the `Mozilla trust store`_. The certificates were only updated
once for each Requests version. When ``certifi`` was not installed, this led to
extremely out-of-date certificate bundles when using significantly older
versions of Requests.

For the sake of security we recommend upgrading certifi frequently!

.. _HTTP persistent connection: https://en.wikipedia.org/wiki/HTTP_persistent_connection
.. _connection pooling: https://urllib3.readthedocs.io/en/latest/reference/index.html#module-urllib3.connectionpool
.. _certifi: https://certifiio.readthedocs.io/
.. _Mozilla trust store: https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

.. _body-content-workflow:

Body Content Workflow
---------------------

By default, when you make a request, the body of the response is downloaded
immediately. You can override this behaviour and defer downloading the response
body until you access the :attr:`Response.content <requests.Response.content>`
attribute with the ``stream`` parameter::

    tarball_url = 'https://github.com/requests/requests/tarball/master'
    r = requests.get(tarball_url, stream=True)

At this point only the response headers have been downloaded and the connection
remains open, hence allowing us to make content retrieval conditional::

    if int(r.headers['content-length']) < TOO_LONG:
      content = r.content
      ...

You can further control the workflow by use of the :meth:`Response.iter_content() <requests.Response.iter_content>`
and :meth:`Response.iter_lines() <requests.Response.iter_lines>` methods.
Alternatively, you can read the undecoded body from the underlying
urllib3 :class:`urllib3.HTTPResponse <urllib3.response.HTTPResponse>` at
:attr:`Response.raw <requests.Response.raw>`.

If you set ``stream`` to ``True`` when making a request, Requests cannot
release the connection back to the pool unless you consume all the data or call
:meth:`Response.close <requests.Response.close>`. This can lead to
inefficiency with connections. If you find yourself partially reading request
bodies (or not reading them at all) while using ``stream=True``, you should
make the request within a ``with`` statement to ensure it's always closed::

    with requests.get('https://httpbin.org/get', stream=True) as r:
        # Do things with the response here.

.. _keep-alive:

Keep-Alive
----------

Excellent news — thanks to urllib3, keep-alive is 100% automatic within a session!
Any requests that you make within a session will automatically reuse the appropriate
connection!

Note that connections are only released back to the pool for reuse once all body
data has been read; be sure to either set ``stream`` to ``False`` or read the
``content`` property of the ``Response`` object.

.. _streaming-uploads:

Streaming Uploads
-----------------

Requests supports streaming uploads, which allow you to send large streams or
files without reading them into memory. To stream and upload, simply provide a
file-like object for your body::

    with open('massive-body', 'rb') as f:
        requests.post('http://some.url/streamed', data=f)

.. warning:: It is strongly recommended that you open files in :ref:`binary
             mode <tut-files>`. This is because Requests may attempt to provide
             the ``Content-Length`` header for you, and if it does this value
             will be set to the number of *bytes* in the file. Errors may occur
             if you open the file in *text mode*.


.. _chunk-encoding:

Chunk-Encoded Requests
----------------------

Requests also supports Chunked transfer encoding for outgoing and incoming requests.
To send a chunk-encoded request, simply provide a generator (or any iterator without
a length) for your body::

    def gen():
        yield 'hi'
        yield 'there'

    requests.post('http://some.url/chunked', data=gen())

For chunked encoded responses, it's best to iterate over the data using
:meth:`Response.iter_content() <requests.Response.iter_content>`. In
an ideal situation you'll have set ``stream=True`` on the request, in which
case you can iterate chunk-by-chunk by calling ``iter_content`` with a ``chunk_size``
parameter of ``None``. If you want to set a maximum size of the chunk,
you can set a ``chunk_size`` parameter to any integer.


.. _multipart:

POST Multiple Multipart-Encoded Files
-------------------------------------

You can send multiple files in one request. For example, suppose you want to
upload image files to an HTML form with a multiple file field 'images'::

    <input type="file" name="images" multiple="true" required="true"/>

To do that, just set files to a list of tuples of ``(form_field_name, file_info)``::

    >>> url = 'https://httpbin.org/post'
    >>> multiple_files = [
            ('images', ('foo.png', open('foo.png', 'rb'), 'image/png')),
            ('images', ('bar.png', open('bar.png', 'rb'), 'image/png'))]
    >>> r = requests.post(url, files=multiple_files)
    >>> r.text
    {
      ...
      'files': {'images': 'data:image/png;base64,iVBORw ....'}
      'Content-Type': 'multipart/form-data; boundary=3131623adb2043caaeb5538cc7aa0b3a',
      ...
    }

.. warning:: It is strongly recommended that you open files in :ref:`binary
             mode <tut-files>`. This is because Requests may attempt to provide
             the ``Content-Length`` header for you, and if it does this value
             will be set to the number of *bytes* in the file. Errors may occur
             if you open the file in *text mode*.


.. _event-hooks:

Event Hooks
-----------

Requests has a hook system that you can use to manipulate portions of
the request process, or signal event handling.

Available hooks:

``response``:
    The response generated from a Request.


You can assign a hook function on a per-request basis by passing a
``{hook_name: callback_function}`` dictionary to the ``hooks`` request
parameter::

    hooks={'response': print_url}

That ``callback_function`` will receive a chunk of data as its first
argument.

::

    def print_url(r, *args, **kwargs):
        print(r.url)

If an error occurs while executing your callback, a warning is given.

If the callback function returns a value, it is assumed that it is to
replace the data that was passed in. If the function doesn't return
anything, nothing else is affected.

::

    def record_hook(r, *args, **kwargs):
        r.hook_called = True
        return r

Let's print some request method arguments at runtime::

    >>> requests.get('https://httpbin.org/', hooks={'response': print_url})
    https://httpbin.org/
    <Response [200]>

You can add multiple hooks to a single request.  Let's call two hooks at once::

    >>> r = requests.get('https://httpbin.org/', hooks={'response': [print_url, record_hook]})
    >>> r.hook_called
    True

You can also add hooks to a ``Session`` instance.  Any hooks you add will then
be called on every request made to the session.  For example::

   >>> s = requests.Session()
   >>> s.hooks['response'].append(print_url)
   >>> s.get('https://httpbin.org/')
    https://httpbin.org/
    <Response [200]>

A ``Session`` can have multiple hooks, which will be called in the order
they are added.

.. _custom-auth:

Custom Authentication
---------------------

Requests allows you to use specify your own authentication mechanism.

Any callable which is passed as the ``auth`` argument to a request method will
have the opportunity to modify the request before it is dispatched.

Authentication implementations are subclasses of :class:`AuthBase <requests.auth.AuthBase>`,
and are easy to define. Requests provides two common authentication scheme
implementations in ``requests.auth``: :class:`HTTPBasicAuth <requests.auth.HTTPBasicAuth>` and
:class:`HTTPDigestAuth <requests.auth.HTTPDigestAuth>`.

Let's pretend that we have a web service that will only respond if the
``X-Pizza`` header is set to a password value. Unlikely, but just go with it.

::

    from requests.auth import AuthBase

    class PizzaAuth(AuthBase):
        """Attaches HTTP Pizza Authentication to the given Request object."""
        def __init__(self, username):
            # setup any auth-related data here
            self.username = username

        def __call__(self, r):
            # modify and return the request
            r.headers['X-Pizza'] = self.username
            return r

Then, we can make a request using our Pizza Auth::

    >>> requests.get('http://pizzabin.org/admin', auth=PizzaAuth('kenneth'))
    <Response [200]>

.. _streaming-requests:

Streaming Requests
------------------

With :meth:`Response.iter_lines() <requests.Response.iter_lines>` you can easily
iterate over streaming APIs such as the `Twitter Streaming
API <https://dev.twitter.com/streaming/overview>`_. Simply
set ``stream`` to ``True`` and iterate over the response with
:meth:`~requests.Response.iter_lines()`::

    import json
    import requests

    r = requests.get('https://httpbin.org/stream/20', stream=True)

    for line in r.iter_lines():

        # filter out keep-alive new lines
        if line:
            decoded_line = line.decode('utf-8')
            print(json.loads(decoded_line))

When using `decode_unicode=True` with
:meth:`Response.iter_lines() <requests.Response.iter_lines>` or
:meth:`Response.iter_content() <requests.Response.iter_content>`, you'll want
to provide a fallback encoding in the event the server doesn't provide one::

    r = requests.get('https://httpbin.org/stream/20', stream=True)

    if r.encoding is None:
        r.encoding = 'utf-8'

    for line in r.iter_lines(decode_unicode=True):
        if line:
            print(json.loads(line))

.. warning::

    :meth:`~requests.Response.iter_lines()` is not reentrant safe.
    Calling this method multiple times causes some of the received data
    being lost. In case you need to call it from multiple places, use
    the resulting iterator object instead::

        lines = r.iter_lines()
        # Save the first line for later or just skip it

        first_line = next(lines)

        for line in lines:
            print(line)

.. _proxies:

Proxies
-------

If you need to use a proxy, you can configure individual requests with the
``proxies`` argument to any request method::

    import requests

    proxies = {
      'http': 'http://10.10.1.10:3128',
      'https': 'http://10.10.1.10:1080',
    }

    requests.get('http://example.org', proxies=proxies)

You can also configure proxies by setting the environment variables
``HTTP_PROXY`` and ``HTTPS_PROXY``.

::

    $ export HTTP_PROXY="http://10.10.1.10:3128"
    $ export HTTPS_PROXY="http://10.10.1.10:1080"

    $ python
    >>> import requests
    >>> requests.get('http://example.org')

To use HTTP Basic Auth with your proxy, use the `http://user:password@host/` syntax::

    proxies = {'http': 'http://user:pass@10.10.1.10:3128/'}

To give a proxy for a specific scheme and host, use the
`scheme://hostname` form for the key.  This will match for
any request to the given scheme and exact hostname.

::

    proxies = {'http://10.20.1.128': 'http://10.10.1.10:5323'}

Note that proxy URLs must include the scheme.

SOCKS
^^^^^

.. versionadded:: 2.10.0

In addition to basic HTTP proxies, Requests also supports proxies using the
SOCKS protocol. This is an optional feature that requires that additional
third-party libraries be installed before use.

You can get the dependencies for this feature from ``pip``:

.. code-block:: bash

    $ pip install requests[socks]

Once you've installed those dependencies, using a SOCKS proxy is just as easy
as using a HTTP one::

    proxies = {
        'http': 'socks5://user:pass@host:port',
        'https': 'socks5://user:pass@host:port'
    }

Using the scheme ``socks5`` causes the DNS resolution to happen on the client, rather than on the proxy server. This is in line with curl, which uses the scheme to decide whether to do the DNS resolution on the client or proxy. If you want to resolve the domains on the proxy server, use ``socks5h`` as the scheme.

.. _compliance:

Compliance
----------

Requests is intended to be compliant with all relevant specifications and
RFCs where that compliance will not cause difficulties for users. This
attention to the specification can lead to some behaviour that may seem
unusual to those not familiar with the relevant specification.

Encodings
^^^^^^^^^

When you receive a response, Requests makes a guess at the encoding to
use for decoding the response when you access the :attr:`Response.text
<requests.Response.text>` attribute. Requests will first check for an
encoding in the HTTP header, and if none is present, will use `chardet
<https://pypi.org/project/chardet/>`_ to attempt to guess the encoding.

The only time Requests will not do this is if no explicit charset
is present in the HTTP headers **and** the ``Content-Type``
header contains ``text``. In this situation, `RFC 2616
<https://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.7.1>`_ specifies
that the default charset must be ``ISO-8859-1``. Requests follows the
specification in this case. If you require a different encoding, you can
manually set the :attr:`Response.encoding <requests.Response.encoding>`
property, or use the raw :attr:`Response.content <requests.Response.content>`.

.. _http-verbs:

HTTP Verbs
----------

Requests provides access to almost the full range of HTTP verbs: GET, OPTIONS,
HEAD, POST, PUT, PATCH and DELETE. The following provides detailed examples of
using these various verbs in Requests, using the GitHub API.

We will begin with the verb most commonly used: GET. HTTP GET is an idempotent
method that returns a resource from a given URL. As a result, it is the verb
you ought to use when attempting to retrieve data from a web location. An
example usage would be attempting to get information about a specific commit
from GitHub. Suppose we wanted commit ``a050faf`` on Requests. We would get it
like so::

    >>> import requests
    >>> r = requests.get('https://api.github.com/repos/requests/requests/git/commits/a050faf084662f3a352dd1a941f2c7c9f886d4ad')

We should confirm that GitHub responded correctly. If it has, we want to work
out what type of content it is. Do this like so::

    >>> if r.status_code == requests.codes.ok:
    ...     print(r.headers['content-type'])
    ...
    application/json; charset=utf-8

So, GitHub returns JSON. That's great, we can use the :meth:`r.json
<requests.Response.json>` method to parse it into Python objects.

::

    >>> commit_data = r.json()

    >>> print(commit_data.keys())
    [u'committer', u'author', u'url', u'tree', u'sha', u'parents', u'message']

    >>> print(commit_data[u'committer'])
    {u'date': u'2012-05-10T11:10:50-07:00', u'email': u'me@kennethreitz.com', u'name': u'Kenneth Reitz'}

    >>> print(commit_data[u'message'])
    makin' history

So far, so simple. Well, let's investigate the GitHub API a little bit. Now,
we could look at the documentation, but we might have a little more fun if we
use Requests instead. We can take advantage of the Requests OPTIONS verb to
see what kinds of HTTP methods are supported on the url we just used.

::

    >>> verbs = requests.options(r.url)
    >>> verbs.status_code
    500

Uh, what? That's unhelpful! Turns out GitHub, like many API providers, don't
actually implement the OPTIONS method. This is an annoying oversight, but it's
OK, we can just use the boring documentation. If GitHub had correctly
implemented OPTIONS, however, they should return the allowed methods in the
headers, e.g.

::

    >>> verbs = requests.options('http://a-good-website.com/api/cats')
    >>> print(verbs.headers['allow'])
    GET,HEAD,POST,OPTIONS

Turning to the documentation, we see that the only other method allowed for
commits is POST, which creates a new commit. As we're using the Requests repo,
we should probably avoid making ham-handed POSTS to it. Instead, let's play
with the Issues feature of GitHub.

This documentation was added in response to
`Issue #482 <https://github.com/requests/requests/issues/482>`_. Given that
this issue already exists, we will use it as an example. Let's start by getting it.

::

    >>> r = requests.get('https://api.github.com/repos/requests/requests/issues/482')
    >>> r.status_code
    200

    >>> issue = json.loads(r.text)

    >>> print(issue[u'title'])
    Feature any http verb in docs

    >>> print(issue[u'comments'])
    3

Cool, we have three comments. Let's take a look at the last of them.

::

    >>> r = requests.get(r.url + u'/comments')
    >>> r.status_code
    200

    >>> comments = r.json()

    >>> print(comments[0].keys())
    [u'body', u'url', u'created_at', u'updated_at', u'user', u'id']

    >>> print(comments[2][u'body'])
    Probably in the "advanced" section

Well, that seems like a silly place. Let's post a comment telling the poster
that he's silly. Who is the poster, anyway?

::

    >>> print(comments[2][u'user'][u'login'])
    kennethreitz

OK, so let's tell this Kenneth guy that we think this example should go in the
quickstart guide instead. According to the GitHub API doc, the way to do this
is to POST to the thread. Let's do it.

::

    >>> body = json.dumps({u"body": u"Sounds great! I'll get right on it!"})
    >>> url = u"https://api.github.com/repos/requests/requests/issues/482/comments"

    >>> r = requests.post(url=url, data=body)
    >>> r.status_code
    404

Huh, that's weird. We probably need to authenticate. That'll be a pain, right?
Wrong. Requests makes it easy to use many forms of authentication, including
the very common Basic Auth.

::

    >>> from requests.auth import HTTPBasicAuth
    >>> auth = HTTPBasicAuth('fake@example.com', 'not_a_real_password')

    >>> r = requests.post(url=url, data=body, auth=auth)
    >>> r.status_code
    201

    >>> content = r.json()
    >>> print(content[u'body'])
    Sounds great! I'll get right on it.

Brilliant. Oh, wait, no! I meant to add that it would take me a while, because
I had to go feed my cat. If only I could edit this comment! Happily, GitHub
allows us to use another HTTP verb, PATCH, to edit this comment. Let's do
that.

::

    >>> print(content[u"id"])
    5804413

    >>> body = json.dumps({u"body": u"Sounds great! I'll get right on it once I feed my cat."})
    >>> url = u"https://api.github.com/repos/requests/requests/issues/comments/5804413"

    >>> r = requests.patch(url=url, data=body, auth=auth)
    >>> r.status_code
    200

Excellent. Now, just to torture this Kenneth guy, I've decided to let him
sweat and not tell him that I'm working on this. That means I want to delete
this comment. GitHub lets us delete comments using the incredibly aptly named
DELETE method. Let's get rid of it.

::

    >>> r = requests.delete(url=url, auth=auth)
    >>> r.status_code
    204
    >>> r.headers['status']
    '204 No Content'

Excellent. All gone. The last thing I want to know is how much of my ratelimit
I've used. Let's find out. GitHub sends that information in the headers, so
rather than download the whole page I'll send a HEAD request to get the
headers.

::

    >>> r = requests.head(url=url, auth=auth)
    >>> print(r.headers)
    ...
    'x-ratelimit-remaining': '4995'
    'x-ratelimit-limit': '5000'
    ...

Excellent. Time to write a Python program that abuses the GitHub API in all
kinds of exciting ways, 4995 more times.

.. _custom-verbs:

Custom Verbs
------------

From time to time you may be working with a server that, for whatever reason,
allows use or even requires use of HTTP verbs not covered above. One example of
this would be the MKCOL method some WEBDAV servers use. Do not fret, these can
still be used with Requests. These make use of the built-in ``.request``
method. For example::

    >>> r = requests.request('MKCOL', url, data=data)
    >>> r.status_code
    200 # Assuming your call was correct

Utilising this, you can make use of any method verb that your server allows.


.. _link-headers:

Link Headers
------------

Many HTTP APIs feature Link headers. They make APIs more self describing and
discoverable.

GitHub uses these for `pagination <https://developer.github.com/v3/#pagination>`_
in their API, for example::

    >>> url = 'https://api.github.com/users/kennethreitz/repos?page=1&per_page=10'
    >>> r = requests.head(url=url)
    >>> r.headers['link']
    '<https://api.github.com/users/kennethreitz/repos?page=2&per_page=10>; rel="next", <https://api.github.com/users/kennethreitz/repos?page=6&per_page=10>; rel="last"'

Requests will automatically parse these link headers and make them easily consumable::

    >>> r.links["next"]
    {'url': 'https://api.github.com/users/kennethreitz/repos?page=2&per_page=10', 'rel': 'next'}

    >>> r.links["last"]
    {'url': 'https://api.github.com/users/kennethreitz/repos?page=7&per_page=10', 'rel': 'last'}

.. _transport-adapters:

Transport Adapters
------------------

As of v1.0.0, Requests has moved to a modular internal design. Part of the
reason this was done was to implement Transport Adapters, originally
`described here`_. Transport Adapters provide a mechanism to define interaction
methods for an HTTP service. In particular, they allow you to apply per-service
configuration.

Requests ships with a single Transport Adapter, the :class:`HTTPAdapter
<requests.adapters.HTTPAdapter>`. This adapter provides the default Requests
interaction with HTTP and HTTPS using the powerful `urllib3`_ library. Whenever
a Requests :class:`Session <requests.Session>` is initialized, one of these is
attached to the :class:`Session <requests.Session>` object for HTTP, and one
for HTTPS.

Requests enables users to create and use their own Transport Adapters that
provide specific functionality. Once created, a Transport Adapter can be
mounted to a Session object, along with an indication of which web services
it should apply to.

::

    >>> s = requests.Session()
    >>> s.mount('https://github.com/', MyAdapter())

The mount call registers a specific instance of a Transport Adapter to a
prefix. Once mounted, any HTTP request made using that session whose URL starts
with the given prefix will use the given Transport Adapter.

Many of the details of implementing a Transport Adapter are beyond the scope of
this documentation, but take a look at the next example for a simple SSL use-
case. For more than that, you might look at subclassing the
:class:`BaseAdapter <requests.adapters.BaseAdapter>`.

Example: Specific SSL Version
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Requests team has made a specific choice to use whatever SSL version is
default in the underlying library (`urllib3`_). Normally this is fine, but from
time to time, you might find yourself needing to connect to a service-endpoint
that uses a version that isn't compatible with the default.

You can use Transport Adapters for this by taking most of the existing
implementation of HTTPAdapter, and adding a parameter *ssl_version* that gets
passed-through to `urllib3`. We'll make a Transport Adapter that instructs the
library to use SSLv3::

    import ssl
    from urllib3.poolmanager import PoolManager

    from requests.adapters import HTTPAdapter


    class Ssl3HttpAdapter(HTTPAdapter):
        """"Transport adapter" that allows us to use SSLv3."""

        def init_poolmanager(self, connections, maxsize, block=False):
            self.poolmanager = PoolManager(
                num_pools=connections, maxsize=maxsize,
                block=block, ssl_version=ssl.PROTOCOL_SSLv3)

.. _`described here`: https://www.kennethreitz.org/essays/the-future-of-python-http
.. _`urllib3`: https://github.com/shazow/urllib3

.. _blocking-or-nonblocking:

Blocking Or Non-Blocking?
-------------------------

With the default Transport Adapter in place, Requests does not provide any kind
of non-blocking IO. The :attr:`Response.content <requests.Response.content>`
property will block until the entire response has been downloaded. If
you require more granularity, the streaming features of the library (see
:ref:`streaming-requests`) allow you to retrieve smaller quantities of the
response at a time. However, these calls will still block.

If you are concerned about the use of blocking IO, there are lots of projects
out there that combine Requests with one of Python's asynchronicity frameworks.
Some excellent examples are `requests-threads`_, `grequests`_,  and `requests-futures`_.

.. _`requests-threads`: https://github.com/requests/requests-threads
.. _`grequests`: https://github.com/kennethreitz/grequests
.. _`requests-futures`: https://github.com/ross/requests-futures

Header Ordering
---------------

In unusual circumstances you may want to provide headers in an ordered manner. If you pass an ``OrderedDict`` to the ``headers`` keyword argument, that will provide the headers with an ordering. *However*, the ordering of the default headers used by Requests will be preferred, which means that if you override default headers in the ``headers`` keyword argument, they may appear out of order compared to other headers in that keyword argument.

If this is problematic, users should consider setting the default headers on a :class:`Session <requests.Session>` object, by setting :attr:`Session <requests.Session.headers>` to a custom ``OrderedDict``. That ordering will always be preferred.

.. _timeouts:

Timeouts
--------

Most requests to external servers should have a timeout attached, in case the
server is not responding in a timely manner. By default, requests do not time
out unless a timeout value is set explicitly. Without a timeout, your code may
hang for minutes or more.

The **connect** timeout is the number of seconds Requests will wait for your
client to establish a connection to a remote machine (corresponding to the
`connect()`_) call on the socket. It's a good practice to set connect timeouts
to slightly larger than a multiple of 3, which is the default `TCP packet
retransmission window <https://www.hjp.at/doc/rfc/rfc2988.txt>`_.

Once your client has connected to the server and sent the HTTP request, the
**read** timeout is the number of seconds the client will wait for the server
to send a response. (Specifically, it's the number of seconds that the client
will wait *between* bytes sent from the server. In 99.9% of cases, this is the
time before the server sends the first byte).

If you specify a single value for the timeout, like this::

    r = requests.get('https://github.com', timeout=5)

The timeout value will be applied to both the ``connect`` and the ``read``
timeouts. Specify a tuple if you would like to set the values separately::

    r = requests.get('https://github.com', timeout=(3.05, 27))

If the remote server is very slow, you can tell Requests to wait forever for
a response, by passing None as a timeout value and then retrieving a cup of
coffee.

::

    r = requests.get('https://github.com', timeout=None)

.. _`connect()`: https://linux.die.net/man/2/connect
