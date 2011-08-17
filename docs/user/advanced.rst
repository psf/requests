.. _advanced:

Advanced Usage
==============

This document covers some of Requests more advanced features.


Session Objects
---------------

The Session object allows you to persist certain parameters across
requests. It also establishes a CookieJar and passes it along
to any requests made from the Session instance.

A session object has all the methods of the main Requests API.

Let's persist some cookies across requests::

    with requests.session() as s:

        s.get('http://httpbin.org/cookies/set/sessioncookie/123456789')
        r = s.get("http://httpbin.org/cookies")

        print r.content


Sessions can also be used to provide default data to the request methods::

    headers = {'x-test': 'true'}
    auth = ('user', 'pass')

    with requests.session(auth=auth, headers=headers) as c:

        # both 'x-test' and 'x-test2' are sent
        c.get('http://httpbin.org/headers', header={'x-test2', 'true'})


.. admonition:: Global Settings

    Certain parameters are best set at the ``request.config`` level
    (e.g.. a global proxy, user agent header).


Event Hooks
-----------

Requests has a hook system that allows you . This is useful for