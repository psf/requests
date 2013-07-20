.. _api:

Developer Interface
===================

.. module:: requests

This part of the documentation covers all the interfaces of Requests.  For
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


Lower-Level Classes
~~~~~~~~~~~~~~~~~~~

.. autoclass:: requests.Request
   :inherited-members:

.. autoclass:: Response
   :inherited-members:

Request Sessions
----------------

.. autoclass:: Session
   :inherited-members:

.. autoclass:: requests.adapters.HTTPAdapter
   :inherited-members:


Exceptions
~~~~~~~~~~

.. autoexception:: requests.exceptions.RequestException
.. autoexception:: requests.exceptions.ConnectionError
.. autoexception:: requests.exceptions.HTTPError
.. autoexception:: requests.exceptions.URLRequired
.. autoexception:: requests.exceptions.TooManyRedirects


Status Code Lookup
~~~~~~~~~~~~~~~~~~

.. autofunction:: requests.codes

::

    >>> requests.codes['temporary_redirect']
    307

    >>> requests.codes.teapot
    418

    >>> requests.codes['\o/']
    200

Cookies
~~~~~~~

.. autofunction:: requests.utils.dict_from_cookiejar
.. autofunction:: requests.utils.cookiejar_from_dict
.. autofunction:: requests.utils.add_dict_to_cookiejar


Encodings
~~~~~~~~~

.. autofunction:: requests.utils.get_encodings_from_content
.. autofunction:: requests.utils.get_encoding_from_headers
.. autofunction:: requests.utils.get_unicode_from_response


Classes
~~~~~~~

.. autoclass:: requests.Response
   :inherited-members:

.. autoclass:: requests.Request
   :inherited-members:

.. autoclass:: requests.PreparedRequest
   :inherited-members:

.. _sessionapi:

.. autoclass:: requests.Session
   :inherited-members:

.. autoclass:: requests.adapters.HTTPAdapter
   :inherited-members:


Migrating to 1.x
----------------

This section details the main differences between 0.x and 1.x and is meant
to ease the pain of upgrading.


API Changes
~~~~~~~~~~~

* ``Response.json`` is now a callable and not a property of a response.

  ::

      import requests
      r = requests.get('https://github.com/timeline.json')
      r.json()   # This *call* raises an exception if JSON decoding fails

* The ``Session`` API has changed. Sessions objects no longer take parameters.
  ``Session`` is also now capitalized, but it can still be
  instantiated with a lowercase ``session`` for backwards compatibility.

  ::

      s = requests.Session()    # formerly, session took parameters
      s.auth = auth
      s.headers.update(headers)
      r = s.get('http://httpbin.org/headers')

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
      r = requests.get('https://github.com/timeline.json', stream=True)
      r.raw.read(10)

* The ``config`` parameter to the requests method has been removed. Some of
  these options are now configured on a ``Session`` such as keep-alive and
  maximum number of redirects. The verbosity option should be handled by
  configuring logging.

  ::

      import requests
      import logging

      # these two lines enable debugging at httplib level (requests->urllib3->httplib)
      # you will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
      # the only thing missing will be the response.body which is not logged.
      import httplib
      httplib.HTTPConnection.debuglevel = 1
      
      logging.basicConfig() # you need to initialize logging, otherwise you will not see anything from requests
      logging.getLogger().setLevel(logging.DEBUG)
      requests_log = logging.getLogger("requests.packages.urllib3")
      requests_log.setLevel(logging.DEBUG)
      requests_log.propagate = True
      
      requests.get('http://httpbin.org/headers')



Licensing
~~~~~~~~~

One key difference that has nothing to do with the API is a change in the
license from the ISC_ license to the `Apache 2.0`_ license. The Apache 2.0
license ensures that contributions to Requests are also covered by the Apache
2.0 license.

.. _ISC: http://opensource.org/licenses/ISC
.. _Apache 2.0: http://opensource.org/licenses/Apache-2.0

