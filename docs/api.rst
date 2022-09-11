.. _api:

Developer Interface
===================

.. module:: requests
This part of the documentation covers all the interfaces of Requests. For
parts where Requests depends on external libraries, we document the most
important right here and provide links to the canonical documentation.


Main Interface
--------------

All of Requests' functionality can be accessed by these 7 methods.
They all return an instance of the :class:`Response <Response>` object.

.. autofunction:: request
.. autofunction:: head
.. autofunction:: get
.. autofunction:: post
.. autofunction:: put
.. autofunction:: patch
.. autofunction:: delete

Exceptions
----------
This list contains some of the most commonly encountered exceptions and their descriptions.
This list is not exhaustive. More types of niche exceptions and the error message
that will accompany them can be found at requests-exceptions_. Errors may be thrown
automatically through API functions such as the ``requests.HTTPError`` or thrown
manually through user-specified conditions such as in the ``requests.ReadTimeout``.
Descriptions for both aforementioned exceptions are below.

.. _requests-exceptions: https://github.com/psf/requests/blob/main/requests/exceptions.py

.. autoexception:: requests.RequestException
Serves as a generic exception to catch any errors thrown by the Requests library. 
Useful for preventing uncatched exceptions due to sending HTTP requests.
Can be used in tandem with Python's ``type()`` to check the specific
exception and respond accordingly.

.. autoexception:: requests.ConnectionError
Serves as a generic exception to catch any errors related to establishing a
connection between the client and the server. Is inherited by the
``requests.ConnectTimeout`` exception and could be the result of an
unstable connection from either the client or the server. Requests that
result in this exception are known to be safe to try again.
Multiple requests that result in this error could mean either the
client lacks an internet connection or the server is offline.

.. autoexception:: requests.HTTPError
Comes from the urllib3_ library and is a generic exception to catch errors
related to HTTP warnings, invalid SSL certificates, or proxy server errors. 
Errors of this type are usually on the server's side or invalid use of the server's API.

.. _urllib3: https://github.com/urllib3/urllib3/blob/main/src/urllib3/exceptions.py#L16

.. autoexception:: requests.URLRequired
A derived exception from the ``requests.RequestException`` class. Check the spelling
on the URL and try again. Could also arise due to a domain becoming
inactive and needing to be renewed.

.. autoexception:: requests.TooManyRedirects
A derived exception from the ``requests.RequestException`` class. Happens when the
page requested redirects to another page too many times. Usually happens when
two or more pages redirect to each other in an infinite loop. If this is not the case,
consider requesting a page further down the request pipeline to prevent this error.

.. autoexception:: requests.ConnectTimeout
A derived exception from the ``requests.ConnectionError`` class. Happens when
the request takes too long to establish a connection to the server.
This exception could be the result of unstable internet and this type of
request is safe to try again.

.. autoexception:: requests.ReadTimeout
An exception that occurs when a connection is established with the server,
but the server does not send any data in a given amount of time. The time
for this excpetion can be set by the user and thrown manually using
Python's Time-Library_.

.. _Time-Library: https://docs.python.org/3/library/time.html

.. autoexception:: requests.Timeout
Serves as a generic exception to catch any errors related to timeouts.
Catching this exception will be able to catch both ``requests.ConnectTimeout``
and ``requests.ReadTimeout`` errors. The ``type()`` of the error
can then be checked and responded to accordingly.


Request Sessions
----------------

.. _sessionapi:

.. autoclass:: Session
   :inherited-members:


Lower-Level Classes
-------------------

.. autoclass:: requests.Request
   :inherited-members:

.. autoclass:: Response
   :inherited-members:


Lower-Lower-Level Classes
-------------------------

.. autoclass:: requests.PreparedRequest
   :inherited-members:

.. autoclass:: requests.adapters.BaseAdapter
   :inherited-members:

.. autoclass:: requests.adapters.HTTPAdapter
   :inherited-members:

Authentication
--------------

.. autoclass:: requests.auth.AuthBase
.. autoclass:: requests.auth.HTTPBasicAuth
.. autoclass:: requests.auth.HTTPProxyAuth
.. autoclass:: requests.auth.HTTPDigestAuth



Encodings
---------

.. autofunction:: requests.utils.get_encodings_from_content
.. autofunction:: requests.utils.get_encoding_from_headers
.. autofunction:: requests.utils.get_unicode_from_response


.. _api-cookies:

Cookies
-------

.. autofunction:: requests.utils.dict_from_cookiejar
.. autofunction:: requests.utils.add_dict_to_cookiejar
.. autofunction:: requests.cookies.cookiejar_from_dict

.. autoclass:: requests.cookies.RequestsCookieJar
   :inherited-members:

.. autoclass:: requests.cookies.CookieConflictError
   :inherited-members:



Status Code Lookup
------------------

.. autoclass:: requests.codes

.. automodule:: requests.status_codes


Migrating to 1.x
----------------

This section details the main differences between 0.x and 1.x and is meant
to ease the pain of upgrading.


API Changes
~~~~~~~~~~~

* ``Response.json`` is now a callable and not a property of a response.

  ::

      import requests
      r = requests.get('https://api.github.com/events')
      r.json()   # This *call* raises an exception if JSON decoding fails

* The ``Session`` API has changed. Sessions objects no longer take parameters.
  ``Session`` is also now capitalized, but it can still be
  instantiated with a lowercase ``session`` for backwards compatibility.

  ::

      s = requests.Session()    # formerly, session took parameters
      s.auth = auth
      s.headers.update(headers)
      r = s.get('https://httpbin.org/headers')

* All request hooks have been removed except 'response'.

* Authentication helpers have been broken out into separate modules. See
  requests-oauthlib_ and requests-kerberos_.

.. _requests-oauthlib: https://github.com/requests/requests-oauthlib
.. _requests-kerberos: https://github.com/requests/requests-kerberos

* The parameter for streaming requests was changed from ``prefetch`` to
  ``stream`` and the logic was inverted. In addition, ``stream`` is now
  required for raw response reading.

  ::

      # in 0.x, passing prefetch=False would accomplish the same thing
      r = requests.get('https://api.github.com/events', stream=True)
      for chunk in r.iter_content(8192):
          ...

* The ``config`` parameter to the requests method has been removed. Some of
  these options are now configured on a ``Session`` such as keep-alive and
  maximum number of redirects. The verbosity option should be handled by
  configuring logging.

  ::

      import requests
      import logging

      # Enabling debugging at http.client level (requests->urllib3->http.client)
      # you will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
      # the only thing missing will be the response.body which is not logged.
      try: # for Python 3
          from http.client import HTTPConnection
      except ImportError:
          from httplib import HTTPConnection
      HTTPConnection.debuglevel = 1

      logging.basicConfig() # you need to initialize logging, otherwise you will not see anything from requests
      logging.getLogger().setLevel(logging.DEBUG)
      requests_log = logging.getLogger("urllib3")
      requests_log.setLevel(logging.DEBUG)
      requests_log.propagate = True

      requests.get('https://httpbin.org/headers')



Licensing
~~~~~~~~~

One key difference that has nothing to do with the API is a change in the
license from the ISC_ license to the `Apache 2.0`_ license. The Apache 2.0
license ensures that contributions to Requests are also covered by the Apache
2.0 license.

.. _ISC: https://opensource.org/licenses/ISC
.. _Apache 2.0: https://opensource.org/licenses/Apache-2.0


Migrating to 2.x
----------------


Compared with the 1.0 release, there were relatively few backwards
incompatible changes, but there are still a few issues to be aware of with
this major release.

For more details on the changes in this release including new APIs, links
to the relevant GitHub issues and some of the bug fixes, read Cory's blog_
on the subject.

.. _blog: https://lukasa.co.uk/2013/09/Requests_20/


API Changes
~~~~~~~~~~~

* There were a couple changes to how Requests handles exceptions.
  ``RequestException`` is now a subclass of ``IOError`` rather than
  ``RuntimeError`` as that more accurately categorizes the type of error.
  In addition, an invalid URL escape sequence now raises a subclass of
  ``RequestException`` rather than a ``ValueError``.

  ::

      requests.get('http://%zz/')   # raises requests.exceptions.InvalidURL

  Lastly, ``httplib.IncompleteRead`` exceptions caused by incorrect chunked
  encoding will now raise a Requests ``ChunkedEncodingError`` instead.

* The proxy API has changed slightly. The scheme for a proxy URL is now
  required.

  ::

      proxies = {
        "http": "10.10.1.10:3128",    # use http://10.10.1.10:3128 instead
      }

      # In requests 1.x, this was legal, in requests 2.x,
      #  this raises requests.exceptions.MissingSchema
      requests.get("http://example.org", proxies=proxies)


Behavioural Changes
~~~~~~~~~~~~~~~~~~~~~~~

* Keys in the ``headers`` dictionary are now native strings on all Python
  versions, i.e. bytestrings on Python 2 and unicode on Python 3. If the
  keys are not native strings (unicode on Python 2 or bytestrings on Python 3)
  they will be converted to the native string type assuming UTF-8 encoding.

* Values in the ``headers`` dictionary should always be strings. This has
  been the project's position since before 1.0 but a recent change
  (since version 2.11.0) enforces this more strictly. It's advised to avoid
  passing header values as unicode when possible.
