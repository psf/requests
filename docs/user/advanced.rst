.. _advanced:

Advanced Usage
==============

This document covers some of Requests more advanced features.


Session Objects
---------------

The Session object allows you to persist certain parameters across
requests. It also persists cookies across all requests made from the
Session instance.

A session object has all the methods of the main Requests API.

Let's persist some cookies across requests::

    s = requests.session()

    s.get('http://httpbin.org/cookies/set/sessioncookie/123456789')
    r = s.get("http://httpbin.org/cookies")

    print r.text
    # '{"cookies": {"sessioncookie": "123456789"}}'


Sessions can also be used to provide default data to the request methods::

    headers = {'x-test': 'true'}
    auth = ('user', 'pass')

    with requests.session(auth=auth, headers=headers) as c:

        # both 'x-test' and 'x-test2' are sent
        c.get('http://httpbin.org/headers', headers={'x-test2': 'true'})


Any dictionaries that you pass to a request method will be merged with the session-level values that are set. The method-level parameters override session parameters.

.. admonition:: Remove a Value From a Dict Parameter

    Sometimes you'll want to omit session-level keys from a dict parameter. To do this, you simply set that key's value to ``None`` in the method-level parameter. It will automatically be omitted.

All values that are contained within a session are directly available to you. See the :ref:`Session API Docs <sessionapi>` to learn more.

Request and Response Objects
----------------------------

Whenever a call is made to requests.*() you are doing two major things. First,
you are constructing a ``Request`` object which will be sent of to a server
to request or query some resource. Second, a ``Response`` object is generated
once ``requests`` gets a response back from the server. The response object
contains all of the information returned by the server and also contains the
``Request`` object you created originally. Here is a simple request to get some
very important information from Wikipedia's servers::

    >>> response = requests.get('http://en.wikipedia.org/wiki/Monty_Python')

If we want to access the headers the server sent back to us, we do this::

    >>> response.headers
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

    >>> response.request.headers
    {'Accept-Encoding': 'identity, deflate, compress, gzip',
    'Accept': '*/*', 'User-Agent': 'python-requests/0.13.1'}


SSL Cert Verification
---------------------

Requests can verify SSL certificates for HTTPS requests, just like a web browser. To check a host's SSL certificate, you can use the ``verify`` argument::

    >>> requests.get('https://kennethreitz.com', verify=True)
    requests.exceptions.SSLError: hostname 'kennethreitz.com' doesn't match either of '*.herokuapp.com', 'herokuapp.com'

I don't have SSL setup on this domain, so it fails. Excellent. Github does though::

    >>> requests.get('https://github.com', verify=True)
    <Response [200]>

You can also pass ``verify`` the path to a CA_BUNDLE file for private certs. You can also set the ``REQUESTS_CA_BUNDLE`` environment variable.

Requests can also ignore verifying the SSL certficate if you set ``verify`` to False. ::

    >>> requests.get('https://kennethreitz.com', verify=False)
    <Response [200]>

By default, ``verify`` is set to True. Option ``verify`` only applies to host certs.

You can also specify the local cert file either as a path or key value pair::

    >>> requests.get('https://kennethreitz.com', cert=('/path/server.crt', '/path/key'))
    <Response [200]>

If you specify a wrong path or an invalid cert::

    >>> requests.get('https://kennethreitz.com', cert='/wrong_path/server.pem')
    SSLError: [Errno 336265225] _ssl.c:347: error:140B0009:SSL routines:SSL_CTX_use_PrivateKey_file:PEM lib


Body Content Workflow
---------------------

By default, when you make a request, the body of the response isn't downloaded immediately. The response headers are downloaded when you make a request, but the content isn't downloaded until you access the :class:`Response.content` attribute.

Let's walk through it::

    tarball_url = 'https://github.com/kennethreitz/requests/tarball/master'
    r = requests.get(tarball_url)

The request has been made, but the connection is still open. The response body has not been downloaded yet. ::

    r.content

The content has been downloaded and cached.

You can override this default behavior with the ``prefetch`` parameter::

    r = requests.get(tarball_url, prefetch=True)
    # Blocks until all of request body has been downloaded.


Configuring Requests
--------------------

Sometimes you may want to configure a request to customize its behavior. To do
this, you can pass in a ``config`` dictionary to a request or session. See the :ref:`Configuration API Docs <configurations>` to learn more.


Keep-Alive
----------

Excellent news — thanks to urllib3, keep-alive is 100% automatic within a session! Any requests that you make within a session will automatically reuse the appropriate connection!

Note that connections are only released back to the pool for reuse once all body data has been read; be sure to either set ``prefetch`` to ``True`` or read the ``content`` property of the ``Response`` object.

If you'd like to disable keep-alive, you can simply set the ``keep_alive`` configuration to ``False``::

    s = requests.session()
    s.config['keep_alive'] = False


Asynchronous Requests
----------------------


``requests.async`` has been removed from requests and is now its own repository named `GRequests <https://github.com/kennethreitz/grequests>`_.


Event Hooks
-----------

Requests has a hook system that you can use to manipulate portions of
the request process, or signal event handling.

Available hooks:

``args``:
    A dictionary of the arguments being sent to Request().

``pre_request``:
    The Request object, directly before being sent.

``post_request``:
    The Request object, directly after being sent.

``response``:
    The response generated from a Request.


You can assign a hook function on a per-request basis by passing a
``{hook_name: callback_function}`` dictionary to the ``hooks`` request
parameter::

    hooks=dict(args=print_url)

That ``callback_function`` will receive a chunk of data as its first
argument.

::

    def print_url(args):
        print args['url']

If an error occurs while executing your callback, a warning is given.

If the callback function returns a value, it is assumed that it is to
replace the data that was passed in. If the function doesn't return
anything, nothing else is effected.

Let's print some request method arguments at runtime::

    >>> requests.get('http://httpbin.org', hooks=dict(args=print_url))
    http://httpbin.org
    <Response [200]>

Let's hijack some arguments this time with a new callback::

    def hack_headers(args):
        if args.get('headers') is None:
            args['headers'] = dict()

        args['headers'].update({'X-Testing': 'True'})

        return args

    hooks = dict(args=hack_headers)
    headers = dict(yo=dawg)

And give it a try::

    >>> requests.get('http://httpbin.org/headers', hooks=hooks, headers=headers)
    {
        "headers": {
            "Content-Length": "",
            "Accept-Encoding": "gzip",
            "Yo": "dawg",
            "X-Forwarded-For": "::ffff:24.127.96.129",
            "Connection": "close",
            "User-Agent": "python-requests.org",
            "Host": "httpbin.org",
            "X-Testing": "True",
            "X-Forwarded-Protocol": "",
            "Content-Type": ""
        }
    }


Custom Authentication
---------------------

Requests allows you to use specify your own authentication mechanism.

Any callable which is passed as the ``auth`` argument to a request method will
have the opportunity to modify the request before it is dispatched.

Authentication implementations are subclasses of ``requests.auth.AuthBase``,
and are easy to define. Requests provides two common authentication scheme
implementations in ``requests.auth``: ``HTTPBasicAuth`` and ``HTTPDigestAuth``.

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

Streaming Requests
------------------

With ``requests.Response.iter_lines()`` you can easily iterate over streaming
APIs such as the `Twitter Streaming API <https://dev.twitter.com/docs/streaming-api>`_.

To use the Twitter Streaming API to track the keyword "requests":

::

    import requests
    import json

    r = requests.post('https://stream.twitter.com/1/statuses/filter.json',
        data={'track': 'requests'}, auth=('username', 'password'))

    for line in r.iter_lines():
        if line: # filter out keep-alive new lines
            print json.loads(line)


Verbose Logging
---------------

If you want to get a good look at what HTTP requests are being sent
by your application, you can turn on verbose logging.

To do so, just configure Requests with a stream to write to::

    >>> my_config = {'verbose': sys.stderr}
    >>> requests.get('http://httpbin.org/headers', config=my_config)
    2011-08-17T03:04:23.380175   GET   http://httpbin.org/headers
    <Response [200]>


Proxies
-------

If you need to use a proxy, you can configure individual requests with the
``proxies`` argument to any request method:

::

    import requests

    proxies = {
      "http": "10.10.1.10:3128",
      "https": "10.10.1.10:1080",
    }

    requests.get("http://example.org", proxies=proxies)

You can also configure proxies by environment variables ``HTTP_PROXY`` and ``HTTPS_PROXY``.

::

    $ export HTTP_PROXY="10.10.1.10:3128"
    $ export HTTPS_PROXY="10.10.1.10:1080"
    $ python
    >>> import requests
    >>> requests.get("http://example.org")

To use HTTP Basic Auth with your proxy, use the `http://user:password@host/` syntax:

::

    proxies = {
        "http": "http://user:pass@10.10.1.10:3128/",
    }


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
    >>> r = requests.get('https://api.github.com/repos/kennethreitz/requests/git/commits/a050faf084662f3a352dd1a941f2c7c9f886d4ad')

We should confirm that GitHub responded correctly. If it has, we want to work
out what type of content it is. Do this like so::

    >>> if (r.status_code == requests.codes.ok):
    ...     print r.headers['content-type']
    ...
    application/json; charset=utf-8

So, GitHub returns JSON. That's great, we can use the JSON module to turn it
into Python objects. Because GitHub returned UTF-8, we should use the
``r.text`` method, not the ``r.content`` method. ``r.content`` returns a
bytestring, while ``r.text`` returns a Unicode-encoded string. I have no plans
to perform byte-manipulation on this response, so I want any Unicode code
points encoded.::

    >>> import json
    >>> commit_data = json.loads(r.text)
    >>> print commit_data.keys()
    [u'committer', u'author', u'url', u'tree', u'sha', u'parents', u'message']
    >>> print commit_data[u'committer']
    {u'date': u'2012-05-10T11:10:50-07:00', u'email': u'me@kennethreitz.com', u'name': u'Kenneth Reitz'}
    >>> print commit_data[u'message']
    makin' history

So far, so simple. Well, let's investigate the GitHub API a little bit. Now,
we could look at the documentation, but we might have a little more fun if we
use Requests instead. We can take advantage of the Requests OPTIONS verb to
see what kinds of HTTP methods are supported on the url we just used.::

    >>> verbs = requests.options(r.url)
    >>> verbs.status_code
    500

Uh, what? That's unhelpful! Turns out GitHub, like many API providers, don't
actually implement the OPTIONS method. This is an annoying oversight, but it's
OK, we can just use the boring documentation. If GitHub had correctly
implemented OPTIONS, however, they should return the allowed methods in the
headers, e.g.::

    >>> verbs = requests.options('http://a-good-website.com/api/cats')
    >>> print verbs.headers['allow']
    GET,HEAD,POST,OPTIONS

Turning to the documentation, we see that the only other method allowed for
commits is POST, which creates a new commit. As we're using the Requests repo,
we should probably avoid making ham-handed POSTS to it. Instead, let's play
with the Issues feature of GitHub.

This documentation was added in response to Issue #482. Given that this issue
already exists, we will use it as an example. Let's start by getting it.::

    >>> r = requests.get('https://api.github.com/repos/kennethreitz/requests/issues/482')
    >>> r.status_code
    200
    >>> issue = json.loads(r.text)
    >>> print issue[u'title']
    Feature any http verb in docs
    >>> print issue[u'comments']
    3

Cool, we have three comments. Let's take a look at the last of them.::

    >>> r = requests.get(r.url + u'/comments')
    >>> r.status_code
    200
    >>> comments = json.loads(r.text)
    >>> print comments[0].keys()
    [u'body', u'url', u'created_at', u'updated_at', u'user', u'id']
    >>> print comments[2][u'body']
    Probably in the "advanced" section

Well, that seems like a silly place. Let's post a comment telling the poster
that he's silly. Who is the poster, anyway?::

    >>> print comments[2][u'user'][u'login']
    kennethreitz

OK, so let's tell this Kenneth guy that we think this example should go in the
quickstart guide instead. According to the GitHub API doc, the way to do this
is to POST to the thread. Let's do it.::

    >>> body = json.dumps({u"body": u"Sounds great! I'll get right on it!"})
    >>> url = u"https://api.github.com/repos/kennethreitz/requests/issues/482/comments"
    >>> r = requests.post(url=url, data=body)
    >>> r.status_code
    404

Huh, that's weird. We probably need to authenticate. That'll be a pain, right?
Wrong. Requests makes it easy to use many forms of authentication, including
the very common Basic Auth.::

    >>> from requests.auth import HTTPBasicAuth
    >>> auth = HTTPBasicAuth('fake@example.com', 'not_a_real_password')
    >>> r = requests.post(url=url, data=body, auth=auth)
    >>> r.status_code
    201
    >>> content = json.loads(r.text)
    >>> print content[u'body']
    Sounds great! I'll get right on it.

Brilliant. Oh, wait, no! I meant to add that it would take me a while, because
I had to go feed my cat. If only I could edit this comment! Happily, GitHub
allows us to use another HTTP verb, PATCH, to edit this comment. Let's do
that.::

    >>> print content[u"id"]
    5804413
    >>> body = json.dumps({u"body": u"Sounds great! I'll get right on it once I feed my cat."})
    >>> url = u"https://api.github.com/repos/kennethreitz/requests/issues/comments/5804413"
    >>> r = requests.patch(url=url, data=body, auth=auth)
    >>> r.status_code
    200

Excellent. Now, just to torture this Kenneth guy, I've decided to let him
sweat and not tell him that I'm working on this. That means I want to delete
this comment. GitHub lets us delete comments using the incredibly aptly named
DELETE method. Let's get rid of it.::

    >>> r = requests.delete(url=url, auth=auth)
    >>> r.status_code
    204
    >>> r.headers['status']
    '204 No Content'

Excellent. All gone. The last thing I want to know is how much of my ratelimit
I've used. Let's find out. GitHub sends that information in the headers, so
rather than download the whole page I'll send a HEAD request to get the
headers.::

    >>> r = requests.head(url=url, auth=auth)
    >>> print r.headers
    // ...snip... //
    'x-ratelimit-remaining': '4995'
    'x-ratelimit-limit': '5000'
    // ...snip... //

Excellent. Time to write a Python program that abuses the GitHub API in all
kinds of exciting ways, 4995 more times.
