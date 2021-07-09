.. _faq:

Frequently Asked Questions
==========================

This part of the documentation answers common questions about Requests.

Encoded Data?
-------------

Requests automatically decompresses gzip-encoded responses, and does
its best to decode response content to unicode when possible.

When either the `brotli <https://pypi.org/project/Brotli/>`_ or `brotlicffi <https://pypi.org/project/brotlicffi/>`_
package is installed, requests also decodes Brotli-encoded responses.

You can get direct access to the raw response (and even the socket),
if needed as well.


Custom User-Agents?
-------------------

Requests allows you to easily override User-Agent strings, along with
any other HTTP Header. See `documentation about headers <https://requests.readthedocs.io/en/master/user/quickstart/#custom-headers>`_.



Why not Httplib2?
-----------------

Chris Adams gave an excellent summary on
`Hacker News <http://news.ycombinator.com/item?id=2884406>`_:

    httplib2 is part of why you should use requests: it's far more respectable
    as a client but not as well documented and it still takes way too much code
    for basic operations. I appreciate what httplib2 is trying to do, that
    there's a ton of hard low-level annoyances in building a modern HTTP
    client, but really, just use requests instead. Kenneth Reitz is very
    motivated and he gets the degree to which simple things should be simple
    whereas httplib2 feels more like an academic exercise than something
    people should use to build production systems[1].

    Disclosure: I'm listed in the requests AUTHORS file but can claim credit
    for, oh, about 0.0001% of the awesomeness.

    1. http://code.google.com/p/httplib2/issues/detail?id=96 is a good example:
    an annoying bug which affect many people, there was a fix available for
    months, which worked great when I applied it in a fork and pounded a couple
    TB of data through it, but it took over a year to make it into trunk and
    even longer to make it onto PyPI where any other project which required "
    httplib2" would get the working version.


Python 3 Support?
-----------------

Yes! Requests officially supports Python 2.7 & 3.6+ and PyPy.

Python 2 Support?
-----------------

Yes! We do not have immediate plans to `sunset
<https://www.python.org/doc/sunset-python-2/>`_ our support for Python
2.7. We understand that we have a large user base with varying needs,
and intend to maintain Python 2.7 support within Requests until `pip
stops supporting Python 2.7 (there's no estimated date on that yet)
<https://pip.pypa.io/en/latest/development/release-process/#python-2-support>`_.

That said, it is *highly* recommended users migrate to Python 3.6+ since Python
2.7 is no longer receiving bug fixes or security updates as of January 1, 2020.

What are "hostname doesn't match" errors?
-----------------------------------------

These errors occur when :ref:`SSL certificate verification <verification>`
fails to match the certificate the server responds with to the hostname
Requests thinks it's contacting. If you're certain the server's SSL setup is
correct (for example, because you can visit the site with your browser) and
you're using Python 2.7, a possible explanation is that you need
Server-Name-Indication.

`Server-Name-Indication`_, or SNI, is an official extension to SSL where the
client tells the server what hostname it is contacting. This is important
when servers are using `Virtual Hosting`_. When such servers are hosting
more than one SSL site they need to be able to return the appropriate
certificate based on the hostname the client is connecting to.

Python3 and Python 2.7.9+ include native support for SNI in their SSL modules.
For information on using SNI with Requests on Python < 2.7.9 refer to this
`Stack Overflow answer`_.

.. _`Server-Name-Indication`: https://en.wikipedia.org/wiki/Server_Name_Indication
.. _`virtual hosting`: https://en.wikipedia.org/wiki/Virtual_hosting
.. _`Stack Overflow answer`: https://stackoverflow.com/questions/18578439/using-requests-with-tls-doesnt-give-sni-support/18579484#18579484
