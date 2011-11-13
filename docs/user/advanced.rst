.. _advanced:

Advanced Usage
==============

This document covers some of Requests more advanced features.


Session Objects
---------------

The Session object allows you to persist certain parameters across
requests. It also perstists cookies across all requests made from the
Session instance.

A session object has all the methods of the main Requests API.

Let's persist some cookies across requests::

    s = requests.session()

    s.get('http://httpbin.org/cookies/set/sessioncookie/123456789')
    r = s.get("http://httpbin.org/cookies")

    print r.content
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


Body Content Workflow
----------------------

By default, When you make a request, the body of the response isn't downloaded immediately. The response headers are downloaded when you make a request, but the content isn't downloaded until you access the :class:`Response.content` attribute.

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

Excellent news — thanks to urllib3. keep-alive is 100% automatic within a session! Any requests that you make within a session will automatically reuse the appropriate connection!

If you'd like to disable keep-alive, you can simply set the ``keep_alive`` configuration to ``False``::

    s = requests.session()
    s.config['keep_alive'] = False


Asynchronous Requests
----------------------

Requests has first-class support for concurrent requests, powered
by gevent. This allows you to send a bunch of HTTP requests at the same

First, let's import the async module. Heads up — if you don't have
`gevent <http://pypi.python.org/pypi/gevent>`_ this will fail::

    from requests import async

The ``async`` module has the exact same api as ``requests``, except it
doesn't send the request immediately. Instead, it returns the ``Request``
object.

We can build a list of ``Request`` objects easily::

    urls = [
        'http://python-requests.org',
        'http://httpbin.org',
        'http://python-guide.org',
        'http://kennethreitz.com'
    ]

    rs = [async.get(u) for u in urls]

Now we have a list of ``Request`` objects, ready to be sent. We could send them
one at a time with ``Request.send()``, but that would take a while.  Instead,
we'll send them all at the same time with ``async.map()``.  Using ``async.map()``
will also guarantee execution of the ``response`` hook, described below. ::

    >>> async.map(rs)
    [<Response [200]>, <Response [200]>, <Response [200]>, <Response [200]>]

.. admonition:: Throttling

    The ``map`` function also takes a ``size`` parameter, that specifies the nubmer of connections to make at a time::

        async.map(rs, size=5)


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

    >>> requests.get('http://httpbin', hooks=dict(args=print_url))
    http://httpbin
    <Response [200]>

Let's hijack some arguments this time with a new callback::

    def hack_headers(args):
        if not args[headers]:
            args['headers'] = dict()

        args['headers'].update({'X-Testing': 'True'})

        return args

    hooks = dict(args=hack_headers)
    headers = dict(yo=dawg)

And give it a try::

    >>> requests.get('http://httpbin/headers', hooks=hooks, headers=headers)
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

When you pass our authentication tuple to a request method, the first
string is the type of authentication. 'basic' is inferred if none is
provided.

You can pass in a callable object instead of a string for the first item
in the tuple, and it will be used in place of the built in authentication
callbacks.

Let's pretend that we have a web service that will only respond if the
``X-Pizza`` header is set to a password value. Unlikely, but just go with it.

We simply need to define a callback function that will be used to update the
Request object, right before it is dispatched.

::

    def pizza_auth(r, username):
        """Attaches HTTP Pizza Authentication to the given Request object.
        """
        r.headers['X-Pizza'] = username

        return r

Then, we can make a request using our Pizza Auth::

    >>> requests.get('http://pizzabin.org/admin', auth=(pizza_auth, 'kenneth'))
    <Response [200]>


Verbose Logging
---------------

If you want to get a good look at what HTTP requests are being sent
by your application, you can turn on verbose logging.

To do so, just configure Requests with a stream to write to::

    >>> my_config = {'verbose': sys.stderr}
    >>> requests.get('http://httpbin.org/headers', config=my_config)
    2011-08-17T03:04:23.380175   GET   http://httpbin.org/headers
    <Response [200]>
