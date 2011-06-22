.. _api:

API
===

.. module:: requests

This part of the documentation covers all the interfaces of Requests.  For
parts where Requests depends on external libraries, we document the most
important right here and provide links to the canonical documentation.


Main Interface
--------------

All of Request's functionality can be accessed by these 5 methods. They
all return a :class:`Response <models.Response>` object.

.. autofunction:: head
.. autofunction:: get
.. autofunction:: post
.. autofunction:: put
.. autofunction:: patch
.. autofunction:: delete


-----------


.. autoclass:: requests.models.Response
   :inherited-members:


Exceptions
----------

.. autoexception:: HTTPError

.. autoexception:: RequestException

.. autoexception:: requests.models.AuthenticationError
.. autoexception:: requests.models.URLRequired
.. autoexception:: requests.models.InvalidMethod


Internals
---------

These items are an internal component to Requests, and should never be
seen by the end user (developer). This part of the API documentation
exists for those who are extending the functionality of Requests.

Functions
~~~~~~~~~

.. autofunction:: request

Classes
~~~~~~~

.. autoclass:: requests.models.Request
   :inherited-members:

Structures
~~~~~~~~~~

.. autoclass:: requests.structures.CaseInsensitiveDict
   :inherited-members: