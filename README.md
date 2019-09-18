

<span align="center">
    
<pre>
<img src="https://raw.githubusercontent.com/psf/requests/master/docs/_static/requests-logo-small.png" align="center" />
    <div align="left">
    <p></p>
    <code> Python 3.7.4 (default, Sep  7 2019, 18:27:02)</code>
    <code> >>> <strong>import requests</strong></code>
    <code> >>> r = requests.get('https://api.github.com/repos/psf/requests')</code>
    <code> >>> r.json()["description"]</code>
    <code> 'An elegant & simple HTTP library. Handcrafted, with ♥, for the Python community.'</code>
    </div>
    <p align="center">
This project has been brought to you, with much joy, 
by <a href="https://kennethreitz.org/">Kenneth Reitz</a> & The <a href="https://www.python.org/psf/">Python Software Foundation</a>.
</p>
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
```

Satisfaction guaranteed.

Documentation
-------------

Fantastic documentation is available at
<http://docs.python-requests.org/>, for a limited time only.


✨ 🍰 ✨
