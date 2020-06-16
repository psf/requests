

<span align="center">

<pre>
    <a href="https://requests.readthedocs.io/"><img src="https://raw.githubusercontent.com/psf/requests/master/ext/requests-logo.png" align="center" /></a>
    
    <div align="left">
    <p></p>
    <code> Python 3.7.4 (default, Sep  7 2019, 18:27:02)</code>
    <code> >>> <strong>import requests</strong></code>
    <code> >>> r = requests.get('https://api.github.com/repos/psf/requests')</code>
    <code> >>> r.json()["description"]</code>
    <code> 'A simple, yet elegant HTTP library.'</code>
    </div>

    <p align="center">
This software has been designed for you, with much joy,
by <a href="https://kennethreitz.org/">Kenneth Reitz</a> & is protected by The <a href="https://www.python.org/psf/">Python Software Foundation</a>.
   </p>
</pre>

</span>

<p>&nbsp;</p><p>&nbsp;</p>

<p align="center"><strong>Requests</strong> is an elegant and simple HTTP library for Python, built with ♥.</p>

<p>&nbsp;</p>

```pycon
>>> import requests
>>> r = requests.get('https://api.github.com/user', auth=('user', 'pass'))
>>> r.status_code
200
>>> r.headers['content-type']
'application/json; charset=utf8'
>>> r.encoding
'utf-8'
>>> r.text
'{"type":"User"...'
>>> r.json()
{'disk_usage': 368627, 'private_gists': 484, ...}
```



---------------------------------------------------------------------

<p>&nbsp;</p>

Requests allows you to send HTTP/1.1 requests extremely easily. There’s no need to manually add query strings to your URLs, or to form-encode your `PUT` & `POST` data — but nowadays, just use the `json` method!


Requests is **the most downloaded Python package today**, pulling in around `14M downloads / week`— according to GitHub, Requests is currently [depended upon](https://github.com/psf/requests/network/dependents?package_id=UGFja2FnZS01NzA4OTExNg%3D%3D) by `500,000+` repositories. You may certainly put your trust in this code.


<p>&nbsp;</p>
<p align="center"><a href="https://pepy.tech/project/requests" rel="nofollow"><img src="https://camo.githubusercontent.com/e1dedc9f5ce5cd6b6c699f33d2e812daadcf3645/68747470733a2f2f706570792e746563682f62616467652f7265717565737473" alt="Downloads" data-canonical-src="https://pepy.tech/badge/requests" style="max-width:100%;"></a>
<a href="https://pypi.org/project/requests/" rel="nofollow"><img src="https://camo.githubusercontent.com/6d78aeec0a9a1cfe147ad064bfb99069e298e29b/68747470733a2f2f696d672e736869656c64732e696f2f707970692f707976657273696f6e732f72657175657374732e737667" alt="image" data-canonical-src="https://img.shields.io/pypi/pyversions/requests.svg" style="max-width:100%;"></a>
<a href="https://github.com/psf/requests/graphs/contributors"><img src="https://camo.githubusercontent.com/a70ea15870b38bba9203b969f6a6b7e7845fbb8a/68747470733a2f2f696d672e736869656c64732e696f2f6769746875622f636f6e7472696275746f72732f7073662f72657175657374732e737667" alt="image" data-canonical-src="https://img.shields.io/github/contributors/psf/requests.svg" style="max-width:100%;"></a></p>

<p>&nbsp;</p>

<h2 align="center">Supported Features & Best–Practices</h2>

Requests is ready for the demands of building robust and reliable HTTP–speak applications, for the needs of today.

<pre class="test">
         + International Domains and URLs       + Keep-Alive & Connection Pooling
         + Sessions with Cookie Persistence     + Browser-style SSL Verification
         + Basic & Digest Authentication        + Familiar `dict`–like Cookies
         + Automatic Decompression of Content   + Automatic Content Decoding
         + Automatic Connection Pooling         + Unicode Response Bodies<super>*</super>
         + Multi-part File Uploads              + SOCKS Proxy Support
         + Connection Timeouts                  + Streaming Downloads
         + Automatic honoring of `.netrc`       + Chunked HTTP Requests

                            &, of course, rock–solid stability!
</pre>
</div>

<p align="center">
        ✨ 🍰 ✨&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
</p>

<p>&nbsp;</p>

Requests Module Installation
----------------------------

The recommended way to install the `requests` module is to simply use [`pipenv`](https://pipenv.kennethreitz.org) (or `pip`, of
course):

```console
$ pipenv install requests
Adding requests to Pipfile's [packages]…
✔ Installation Succeeded
…
```

Requests officially supports Python 2.7 & 3.5+.

-------------------------------------

## P.S. — Documentation is available at [`requests.readthedocs.io`](https://requests.readthedocs.io/en/latest/).

<p align="center">
        <a href="https://requests.readthedocs.io/"><img src="https://raw.githubusercontent.com/psf/requests/master/ext/ss.png" align="center" /></a>
</p>


------------------


<p>&nbsp;</p>

<p align="center">
        <a href="https://kennethreitz.org/"><img src="https://raw.githubusercontent.com/psf/requests/master/ext/kr.png" align="center" /></a>
</p>

<p>&nbsp;</p>

<p align="center">
        <a href="https://www.python.org/psf/"><img src="https://raw.githubusercontent.com/psf/requests/master/ext/psf.png" align="center" /></a>
</p>
