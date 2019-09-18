

<span align="center">
    
<pre>
    <img src="https://raw.githubusercontent.com/psf/requests/master/ext/requests-logo.png" align="center" />
    <div align="left">
    <p></p>
    <code> Python 3.7.4 (default, Sep  7 2019, 18:27:02)</code>
    <code> >>> <strong>import requests</strong></code>
    <code> >>> r = requests.get('https://api.github.com/repos/psf/requests')</code>
    <code> >>> r.json()["description"]</code>
    <code> 'An elegant & simple HTTP library. Handcrafted, with ♥, for the Python community.'</code>
    </div>
    
<img src="https://github.com/psf/requests/blob/master/ext/flower-of-life.jpg?raw=true" />
    
    <p align="center">
This project has been brought to you, with much joy, 
by <a href="https://kennethreitz.org/">Kenneth Reitz</a> & The <a href="https://www.python.org/psf/">Python Software Foundation</a>.
</p>
    <img src="https://github.com/psf/requests/blob/master/ext/flourish.png?raw=true" />
</pre>  
   
<p></p>

</span>

---------------------


<p align="center"><strong>Requests</strong> is an elegant and simple HTTP library for Python, built with ♥</p>

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
u'{"type":"User"...'
>>> r.json()
{u'disk_usage': 368627, u'private_gists': 484, ...}
```

<p align="center"><a href="https://pepy.tech/project/requests" rel="nofollow"><img src="https://camo.githubusercontent.com/e1dedc9f5ce5cd6b6c699f33d2e812daadcf3645/68747470733a2f2f706570792e746563682f62616467652f7265717565737473" alt="Downloads" data-canonical-src="https://pepy.tech/badge/requests" style="max-width:100%;"></a>
<a href="https://pypi.org/project/requests/" rel="nofollow"><img src="https://camo.githubusercontent.com/6d78aeec0a9a1cfe147ad064bfb99069e298e29b/68747470733a2f2f696d672e736869656c64732e696f2f707970692f707976657273696f6e732f72657175657374732e737667" alt="image" data-canonical-src="https://img.shields.io/pypi/pyversions/requests.svg" style="max-width:100%;"></a>
<a href="https://github.com/psf/requests/graphs/contributors"><img src="https://camo.githubusercontent.com/a70ea15870b38bba9203b969f6a6b7e7845fbb8a/68747470733a2f2f696d672e736869656c64732e696f2f6769746875622f636f6e7472696275746f72732f7073662f72657175657374732e737667" alt="image" data-canonical-src="https://img.shields.io/github/contributors/psf/requests.svg" style="max-width:100%;"></a></p>

---------------------------------------------------------------------

Requests allows you to send *organic, grass-fed* HTTP/1.1 requests,
without the need for manual labor. There's no need to manually add query
strings to your URLs, or to form-encode your POST data. Keep-alive and
HTTP connection pooling are 100% automatic, thanks to
[urllib3](https://github.com/shazow/urllib3).

Besides, all the cool kids are doing it. Requests is one of the most
downloaded Python packages of all time, pulling about 60,000,000
downloads every month. You don't want to be left out!

<h2 align="center">Supported Features & Best–Practices</h2>

Requests is ready for the demands of building robust and reliable HTTP–speaking applications, on today's web (or your own infrastructure).

<pre class="test">
International Domains and URLs      Keep-Alive & Connection Pooling
Sessions with Cookie Persistence    Browser-style SSL Verification 
Basic & Digest Authentication       Familiar `dict`–like Cookies   
Automatic Decompression of Content  Automatic Content Decoding     
Automatic Connection Pooling        Unicode Response Bodies<super>*</super>
Multi-part File Uploads             SOCKS Proxy Support            
Connection Timeouts                 Streaming Downloads
Automatic honoring of `.netrc`      Chunked HTTP Requests          
              
                 &, of course, rock–solid stability!
</pre>


</div>

Requests officially supports Python 2.7 & 3.4–3.8, and runs great on
PyPy.

Installation
------------

To install **Requests**, simply use [**pipenv**](http://pipenv.org/) (or **pip**, of
course):

```console
$ pipenv install requests
Adding requests to Pipfile's [packages]…
✔ Installation Succeeded
…
```

Satisfaction guaranteed.

Documentation
-------------

Fantastic documentation is available at
<http://docs.python-requests.org/>, for a limited time only.


✨ 🍰 ✨
