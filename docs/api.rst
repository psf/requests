.. _api:

API
===

.. module:: requests

This part of the documentation covers all the interfaces of Requests.  For
parts where Requests depends on external libraries, we document the most
important right here and provide links to the canonical documentation.


Main Interface
--------------

All of Request's functionality can be accessed by these 7 methods.
They all return an instance of the :class:`Response <Response>` object.

.. autofunction:: request
.. autofunction:: head
.. autofunction:: get
.. autofunction:: post
.. autofunction:: put
.. autofunction:: patch
.. autofunction:: delete


-----------


.. autoclass:: Response
   :inherited-members:

Async
-----

.. module:: requests.async


.. autofunction:: map
.. autofunction:: request
.. autofunction:: head
.. autofunction:: get
.. autofunction:: post
.. autofunction:: put
.. autofunction:: patch
.. autofunction:: delete



Utilities
---------

These functions are used internally, but may be useful outside of
Requests.

.. module:: requests.utils

Cookies
~~~~~~~

.. autofunction:: dict_from_cookiejar
.. autofunction:: cookiejar_from_dict
.. autofunction:: add_dict_to_cookiejar


Encodings
~~~~~~~~~

.. autofunction:: get_encodings_from_content
.. autofunction:: get_encoding_from_headers
.. autofunction:: get_unicode_from_response
.. autofunction:: decode_gzip


Internals
---------

These items are an internal component to Requests, and should never be
seen by the end user (developer). This part of the API documentation
exists for those who are extending the functionality of Requests.

Exceptions
~~~~~~~~~~

.. module:: requests

.. autoexception:: HTTPError

.. autoexception:: RequestException

.. autoexception:: AuthenticationError
.. autoexception:: URLRequired
.. autoexception:: InvalidMethod
.. autoexception:: TooManyRedirects



Classes
~~~~~~~

.. autoclass:: requests.Request
   :inherited-members:


