Feature Overview
================

Requests is designed to solve a 90% use case — making simple requests. While most
HTTP libraries are extremely extensible, they often attempt to support the entire HTTP Spec.
This often leads to extremely messy and cumbersome APIs, as is the case with urllib2. Requests abandons support for edge-cases, and focuses on the essentials.


.. _features:

Requests Can:
-------------

- Make **GET**, **POST**, **PUT**, **DELETE**, and **HEAD** requests.
- Handle HTTP and HTTPS Requests
- Add Request headers (with a simple dictionary)
- URLEncode your Form Data (with a simple dictionary)
- Add Multi-part File Uploads (with a simple dictionary)
- Handle CookieJars (with a single parameter)
- Add HTTP Authentication (with a single parameter)
- Handle redirects (with history)
- Automatically decompress GZip'd responses
- Support Unicode URLs
- Gracefully timeout
- Interface with Eventlet & Gevent


Requests Can't:
---------------

- Handle Caching
- Handle Keep-Alives


Quickstart
==========


GET Request
-----------


Adding Parameters
-----------------



Adding Headers
--------------



HTTP Basic Auth
---------------


Tracking Redirects
------------------




HTTP POST (Form Data)
---------------------


HTTP POST (Binary Data)
-----------------------


HTTP POST (Multipart Files)
---------------------------


HTTP PUT
--------


HTTP DELETE
-----------


HTTP HEAD
---------
