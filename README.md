# Requests

**Requests** is a simple, yet elegant, HTTP library.

```python
>>> import requests
>>> r = requests.get('https://httpbin.org/basic-auth/user/pass', auth=('user', 'pass'))
>>> r.status_code
200
>>> r.headers['content-type']
'application/json; charset=utf8'
>>> r.encoding
'utf-8'
>>> r.text
'{"authenticated": true, ...'
>>> r.json()
{'authenticated': True, ...}
```

Requests allows you to send HTTP/1.1 requests extremely easily. There’s no need to manually add query strings to your URLs, or to form-encode your `PUT` & `POST` data — but nowadays, just use the `json` method!

Requests is one of the most downloaded Python packages today, pulling in around `30M downloads / week`— according to GitHub, Requests is currently [depended upon](https://github.com/psf/requests/network/dependents?package_id=UGFja2FnZS01NzA4OTExNg%3D%3D) by `1,000,000+` repositories. You may certainly put your trust in this code.

[![Downloads](https://static.pepy.tech/badge/requests/month)](https://pepy.tech/project/requests)
[![Supported Versions](https://img.shields.io/pypi/pyversions/requests.svg)](https://pypi.org/project/requests)
[![Contributors](https://img.shields.io/github/contributors/psf/requests.svg)](https://github.com/psf/requests/graphs/contributors)

## Installing Requests and Supported Versions

Requests is available on PyPI:

```console
$ python -m pip install requests
```

Requests officially supports Python 3.8+.

## Supported Features & Best–Practices

Requests is ready for the demands of building robust and reliable HTTP–speaking applications, for the needs of today.

- Keep-Alive & Connection Pooling
- International Domains and URLs
- Sessions with Cookie Persistence
- Browser-style TLS/SSL Verification
- Basic & Digest Authentication
- Familiar `dict`–like Cookies
- Automatic Content Decompression and Decoding
- Multi-part File Uploads
- SOCKS Proxy Support
- Connection Timeouts
- Streaming Downloads
- Automatic honoring of `.netrc`
- Chunked HTTP Requests

## API Reference and User Guide available on [Read the Docs](https://requests.readthedocs.io)

[![Read the Docs](https://raw.githubusercontent.com/psf/requests/main/ext/ss.png)](https://requests.readthedocs.io)

## Cloning the repository

When cloning the Requests repository, you may need to add the `-c
fetch.fsck.badTimezone=ignore` flag to avoid an error about a bad commit (see
[this issue](https://github.com/psf/requests/issues/2690) for more background):

```shell
git clone -c fetch.fsck.badTimezone=ignore https://github.com/psf/requests.git
```

You can also apply this setting to your global Git config:

```shell
git config --global fetch.fsck.badTimezone ignore
```

---

[![Kenneth Reitz](https://raw.githubusercontent.com/psf/requests/main/ext/kr.png)](https://kennethreitz.org) [![Python Software Foundation](https://raw.githubusercontent.com/psf/requests/main/ext/psf.png)](https://www.python.org/psf)


## Setting Up a Local Development Environment

To set up a local development environment and run tests, follow these steps:

1. Fork the Requests repository on GitHub and clone your forked repository to your local machine.

git clone https://github.com/<your_username>/requests.git


2. Change to the cloned repository's directory.

cd requests


3. Create a virtual environment to isolate the dependencies for the project.

python -m venv venv


4. Activate the virtual environment.

- On macOS and Linux:

  ```
  source venv/bin/activate
  ```

- On Windows:

  ```
  .\venv\Scripts\activate
  ```

5. Install the required dependencies for the project.

pip install -r requirements.txt


6. Install the Requests library in editable mode, so you can make changes to the source code and see the effects immediately.

pip install -e .


7. Run the tests to make sure everything is set up correctly.

pytest

After setting up the environment, you can start making changes to the code and run tests 