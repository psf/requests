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

.. autoexception:: requests.RequestException
.. autoexception:: requests.ConnectionError
.. autoexception:: requests.HTTPError
.. autoexception:: requests.URLRequired
.. autoexception:: requests.TooManyRedirects
.. autoexception:: requests.ConnectTimeout
.. autoexception:: requests.ReadTimeout
.. autoexception:: requests.Timeout
.. autoexception:: requests.JSONDecodeError


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
