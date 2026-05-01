# HTTP Core

[![Test Suite](https://github.com/encode/httpcore/workflows/Test%20Suite/badge.svg)](https://github.com/encode/httpcore/actions)
[![Package version](https://badge.fury.io/py/httpcore.svg)](https://pypi.org/project/httpcore/)

> *Do one thing, and do it well.*

The HTTP Core package provides a minimal low-level HTTP client, which does
one thing only. Sending HTTP requests.

It does not provide any high level model abstractions over the API,
does not handle redirects, multipart uploads, building authentication headers,
transparent HTTP caching, URL parsing, session cookie handling,
content or charset decoding, handling JSON, environment based configuration
defaults, or any of that Jazz.

Some things HTTP Core does do:

* Sending HTTP requests.
* Thread-safe / task-safe connection pooling.
* HTTP(S) proxy & SOCKS proxy support.
* Supports HTTP/1.1 and HTTP/2.
* Provides both sync and async interfaces.
* Async backend support for `asyncio` and `trio`.

## Requirements

Python 3.8+

## Installation

For HTTP/1.1 only support, install with:

```shell
$ pip install httpcore
```

There are also a number of optional extras available...

```shell
$ pip install httpcore['asyncio,trio,http2,socks']
```

## Sending requests

Send an HTTP request:

```python
import httpcore

response = httpcore.request("GET", "https://www.example.com/")

print(response)
# <Response [200]>
print(response.status)
# 200
print(response.headers)
# [(b'Accept-Ranges', b'bytes'), (b'Age', b'557328'), (b'Cache-Control', b'max-age=604800'), ...]
print(response.content)
# b'<!doctype html>\n<html>\n<head>\n<title>Example Domain</title>\n\n<meta charset="utf-8"/>\n ...'
```

The top-level `httpcore.request()` function is provided for convenience. In practice whenever you're working with `httpcore` you'll want to use the connection pooling functionality that it provides.

```python
import httpcore

http = httpcore.ConnectionPool()
response = http.request("GET", "https://www.example.com/")
```

Once you're ready to get going, [head over to the documentation](https://www.encode.io/httpcore/).

## Motivation

You *probably* don't want to be using HTTP Core directly. It might make sense if
you're writing something like a proxy service in Python, and you just want
something at the lowest possible level, but more typically you'll want to use
a higher level client library, such as `httpx`.

The motivation for `httpcore` is:

* To provide a reusable low-level client library, that other packages can then build on top of.
* To provide a *really clear interface split* between the networking code and client logic,
  so that each is easier to understand and reason about in isolation.

## Dependencies

The `httpcore` package has the following dependencies...

* `h11`
* `certifi`

And the following optional extras...

* `anyio` - Required by `pip install httpcore['asyncio']`.
* `trio` - Required by `pip install httpcore['trio']`.
* `h2` - Required by `pip install httpcore['http2']`.
* `socksio` - Required by `pip install httpcore['socks']`.

## Versioning

We use [SEMVER for our versioning policy](https://semver.org/).

For changes between package versions please see our [project changelog](CHANGELOG.md).

We recommend pinning your requirements either the most current major version, or a more specific version range:

```python
pip install 'httpcore==1.*'
```
