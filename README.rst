yieldfrom.Requests: Requests for asyncio
========================================

Requests is an Apache2 Licensed HTTP library, written in Python, for human
beings.

yieldfrom.Requests is the same library, ported to run under Python's asyncio.

Where in regular Requests you would write:

.. code-block:: pycon

    >>> r = requests.get('https://api.github.com', auth=('user', 'pass'))
    >>> r.status_code
    204
    >>> r.headers['content-type']
    'application/json'
    >>> r.text
    ...


in yieldfrom.Requests you write:

.. code-block:: pycon

    >>> r = yield from requests.get('https://api.github.com', auth=('user', 'pass'))
    >>> r.status_code
    204
    >>> r.headers['content-type']
    'application/json'
    >>> yield from r.text
    ...

The *get* method and the *text* property involve I/O latency, hence are called as coroutines.
The headers and status_code attributes are still plain attributes.


The feature set is the same as the original, though a few methods work slightly differently.

The .stream() method does not stream, but preloads all data, and simulates a stream, so existing
dependencies can work with minimal conversion.

