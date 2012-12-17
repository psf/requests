.. _authentication:

Authentication
==============

This document discusses using various kinds of authentication with Requests.

Many web services require authentication, and there are many different types.
Below, we outline various forms of authentication available in Requests, from
the simple to the complex.


Basic Authentication
--------------------

Many web services that require authentication accept HTTP Basic Auth. This is
the simplest kind, and Requests supports it straight out of the box.

Making requests with HTTP Basic Auth is very simple::

    >>> from requests.auth import HTTPBasicAuth
    >>> requests.get('https://api.github.com/user', auth=HTTPBasicAuth('user', 'pass'))
    <Response [200]>

In fact, HTTP Basic Auth is so common that Requests provides a handy shorthand
for using it::

    >>> requests.get('https://api.github.com/user', auth=('user', 'pass'))
    <Response [200]>

Providing the credentials in a tuple like this is exactly the same as the
``HTTPBasicAuth`` example above.


Digest Authentication
---------------------

Another very popular form of HTTP Authentication is Digest Authentication,
and Requests supports this out of the box as well::

    >>> from requests.auth import HTTPDigestAuth
    >>> url = 'http://httpbin.org/digest-auth/auth/user/pass'
    >>> requests.get(url, auth=HTTPDigestAuth('user', 'pass'))
    <Response [200]>


Other Authentication
--------------------

Requests is designed to allow other forms of authentication to be easily and
quickly plugged in. Members of the open-source community frequently write
authentication handlers for more complicated or less commonly-used forms of
authentication. Some of the best have been brought together under the
`Requests organization`_, including:

- OAuth_
- Kerberos_
- NTLM_

If you want to use any of these forms of authentication, go straight to their
Github page and follow the instructions.


New Forms of Authentication
---------------------------

If you can't find a good implementation of the form of authentication you
want, you can implement it yourself. Requests makes it easy to add your own
forms of authentication.

To do so, subclass :class:`requests.auth.AuthBase` and implement the
``__call__()`` method. When an authentication handler is attached to a request,
it is called during request setup. The ``__call__`` method must therefore do
whatever is required to make the authentication work. Some forms of
authentication will additionally add hooks to provide further functionality.

Examples can be found under the `Requests organization`_ and in the
``auth.py`` file.

.. _OAuth: https://github.com/requests/requests-oauthlib
.. _Kerberos: https://github.com/requests/requests-kerberos
.. _NTLM: https://github.com/requests/requests-ntlm
.. _Requests organization: https://github.com/requests

