.. _faq:

Frequently Asked Questions
==========================

This part of the documentation answers common questions about Requests.

Encoded Data?
-------------

Requests automatically decompresses gzip-encoded responses, and does
its best to decode response content to unicode when possible.

You can get direct access to the raw response (and even the socket),
if needed as well.


Custom User-Agents?
-------------------

Requests allows you to easily override User-Agent strings, along with
any other HTTP Header.


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

Yes! Here's a list of Python platforms that are officially
supported:

* Python 2.6
* Python 2.7
* Python 3.1
* Python 3.2
* Python 3.3
* PyPy 1.9
