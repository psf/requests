<span align="center">
<pre>
    <div align="left">
    <code> Python 3.7.4 (default, Sep  7 2019, 18:27:02)</code>
    <code> >>> <strong>import requests</strong></code>
    <code> >>> r = requests.get('https://api.github.com/repos/psf/requests')</code>
    <code> >>> r.json()["description"]</code>
    <code> 'An elegant & simple HTTP library. Handcrafted, with ♥, for the Python community.'</code>
    </div>
    <img src="https://raw.githubusercontent.com/psf/requests/master/docs/_static/requests-logo-small.png" align="right" />
</pre>  
   
</span>

---------------------


**Requests** is an elegant and simple HTTP library for Python, built for human beings.

[![Downloads](https://pepy.tech/badge/requests)](https://pepy.tech/project/requests)
[![image](https://img.shields.io/pypi/pyversions/requests.svg)](https://pypi.org/project/requests/)
[![image](https://img.shields.io/github/contributors/psf/requests.svg)](https://github.com/psf/requests/graphs/contributors)


Behold, the power of Requests:

``` {.sourceCode .python}
>>> import requests
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

[![image]()](http://docs.python-requests.org/)

Requests allows you to send *organic, grass-fed* HTTP/1.1 requests,
without the need for manual labor. There's no need to manually add query
strings to your URLs, or to form-encode your POST data. Keep-alive and
HTTP connection pooling are 100% automatic, thanks to
[urllib3](https://github.com/shazow/urllib3).

Besides, all the cool kids are doing it. Requests is one of the most
downloaded Python packages of all time, pulling about 60,000,000
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

Requests officially supports Python 2.7 & 3.4–3.8, and runs great on
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

1.  Become more familiar with the project by reading our [Contributor's Guide](http://docs.python-requests.org/en/latest/dev/contributing/) and our [development philosophy](http://docs.python-requests.org/en/latest/dev/philosophy/).
2.  Check for open issues or open a fresh issue to start a discussion
    around a feature idea or a bug. There is a [Contributor
    Friendly](https://github.com/psf/requests/issues?direction=desc&labels=Contributor+Friendly&page=1&sort=updated&state=open)
    tag for issues that should be ideal for people who are not very
    familiar with the codebase yet.
3.  Fork [the repository](https://github.com/psf/requests) on
    GitHub to start making your changes to the **master** branch (or
    branch off of it).
4.  Write a test which shows that the bug was fixed or that the feature
    works as expected.
5.  Send a [pull request](https://help.github.com/en/articles/creating-a-pull-request-from-a-fork) and bug the maintainer until it gets merged and
    published. :) Make sure to add yourself to
    [AUTHORS](https://github.com/psf/requests/blob/master/AUTHORS.rst).

