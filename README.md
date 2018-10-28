Requests: HTTP for Humans™
==========================

[![image](https://img.shields.io/pypi/v/requests.svg)](https://pypi.org/project/requests/)
[![image](https://img.shields.io/pypi/l/requests.svg)](https://pypi.org/project/requests/)
[![image](https://img.shields.io/pypi/pyversions/requests.svg)](https://pypi.org/project/requests/)
[![codecov.io](https://codecov.io/github/requests/requests/coverage.svg?branch=master)](https://codecov.io/github/requests/requests)
[![image](https://img.shields.io/github/contributors/requests/requests.svg)](https://github.com/requests/requests/graphs/contributors)
[![image](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg)](https://saythanks.io/to/kennethreitz)

**If you're interested in financially supporting Kenneth Reitz open source, consider [visiting this link](https://cash.me/$KennethReitz). Your support helps tremendously with sustainability of motivation, as Open Source is no longer part of my day job.**

Requests is the only *Non-GMO* HTTP library for Python, safe for human
consumption.

![image](https://farm5.staticflickr.com/4317/35198386374_1939af3de6_k_d.jpg)

Behold, the power of Requests:

``` {.sourceCode .python}
>>> r = requests.get('https://api.github.com/user', auth=('user', 'pass'))
>>> r.status_code
200
>>> r.headers['content-type']
'application/json; charset=utf8'
>>> r.encoding
'utf-8'
>>> r.text
u'{"type":"User"...'
>>> r.json()
{u'disk_usage': 368627, u'private_gists': 484, ...}
```

See [the similar code, sans Requests](https://gist.github.com/973705).

[![image](https://raw.githubusercontent.com/requests/requests/master/docs/_static/requests-logo-small.png)](http://docs.python-requests.org/)

Requests allows you to send *organic, grass-fed* HTTP/1.1 requests,
without the need for manual labor. There's no need to manually add query
strings to your URLs, or to form-encode your POST data. Keep-alive and
HTTP connection pooling are 100% automatic, thanks to
[urllib3](https://github.com/shazow/urllib3).

Besides, all the cool kids are doing it. Requests is one of the most
downloaded Python packages of all time, pulling in over 11,000,000
downloads every month. You don't want to be left out!

Feature Support
---------------

Requests is ready for today's web.

-   International Domains and URLs
-   Keep-Alive & Connection Pooling
-   Sessions with Cookie Persistence
-   Browser-style SSL Verification
-   Basic/Digest Authentication
-   Elegant Key/Value Cookies
-   Automatic Decompression
-   Automatic Content Decoding
-   Unicode Response Bodies
-   Multipart File Uploads
-   HTTP(S) Proxy Support
-   Connection Timeouts
-   Streaming Downloads
-   `.netrc` Support
-   Chunked Requests

Requests officially supports Python 2.7 & 3.4–3.7, and runs great on
PyPy.

Installation
------------

To install Requests, simply use [pipenv](http://pipenv.org/) (or pip, of
course):

``` {.sourceCode .bash}
$ pipenv install requests
✨🍰✨
```

Satisfaction guaranteed.

Documentation
-------------

Fantastic documentation is available at
<http://docs.python-requests.org/>, for a limited time only.

How to Contribute
-----------------

1.  Check for open issues or open a fresh issue to start a discussion
    around a feature idea or a bug. There is a [Contributor
    Friendly](https://github.com/requests/requests/issues?direction=desc&labels=Contributor+Friendly&page=1&sort=updated&state=open)
    tag for issues that should be ideal for people who are not very
    familiar with the codebase yet.
2.  Fork [the repository](https://github.com/requests/requests) on
    GitHub to start making your changes to the **master** branch (or
    branch off of it).
3.  Write a test which shows that the bug was fixed or that the feature
    works as expected.
4.  Send a pull request and bug the maintainer until it gets merged and
    published. :) Make sure to add yourself to
    [AUTHORS](https://github.com/requests/requests/blob/master/AUTHORS.rst).

