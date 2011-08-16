.. _advanced:

Advanced Usage
==============

This document covers more advanced features.

Session Objects
===============

.. module:: requests.session 

The Session object allows you to persist certain parameters across requests.  It also establishes a CookieJar by default and passes it along in any requests made from the Session instance.  For a complete list of allowed parameters, please see the *__attrs__* field in *requests/session.py*. ::

    from requests.session import Session

    s = Session()
    s.get("http://httpbin.org/cookies/set/sessioncookie/123456789")
    r = s.get("http://httpbin.org/cookies")
    print r.content

Note: Certain parameters are best set at the request.config level (i.e. a global proxy, user agent header).
