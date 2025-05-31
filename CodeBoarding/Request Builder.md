```mermaid
graph LR
    Request["Request"]
    PreparedRequest["PreparedRequest"]
    Request -- "prepares" --> PreparedRequest
```
[![CodeBoarding](https://img.shields.io/badge/Generated%20by-CodeBoarding-9cf?style=flat-square)](https://github.com/CodeBoarding/GeneratedOnBoardings)[![Demo](https://img.shields.io/badge/Try%20our-Demo-blue?style=flat-square)](https://www.codeboarding.org/demo)[![Contact](https://img.shields.io/badge/Contact%20us%20-%20codeboarding@gmail.com-lightgrey?style=flat-square)](mailto:codeboarding@gmail.com)

## Component Details

The Request Builder component is responsible for constructing and preparing HTTP requests. It takes raw request data, such as URL, headers, and body, and transforms it into a `PreparedRequest` object, which is ready to be sent by a transport adapter. The process involves encoding the URL, constructing headers, serializing the body, and applying authentication and cookies. The main flow starts with a `Request` object, which is then prepared into a `PreparedRequest` object.

### Request
The Request class represents an HTTP request. It encapsulates the data needed to make a request, such as the URL, HTTP method, headers, and body. It provides a `prepare` method that transforms the request into a `PreparedRequest` object.
- **Related Classes/Methods**: `requests.src.requests.models.Request:__init__` (258:290), `requests.src.requests.models.Request:prepare` (295:310)

### PreparedRequest
The PreparedRequest class represents a prepared HTTP request, ready to be sent. It takes a Request object and performs all the necessary preparation steps, such as preparing the URL, headers, and body. It includes methods for preparing different parts of the request, such as the method, URL, headers, body, content length, authentication, cookies, and hooks.
- **Related Classes/Methods**: `requests.src.requests.models.PreparedRequest:__init__` (334:349), `requests.src.requests.models.PreparedRequest:prepare` (351:377), `requests.src.requests.models.PreparedRequest:copy` (382:391), `requests.src.requests.models.PreparedRequest:prepare_method` (393:397), `requests.src.requests.models.PreparedRequest:prepare_url` (409:481), `requests.src.requests.models.PreparedRequest:prepare_headers` (483:492), `requests.src.requests.models.PreparedRequest:prepare_body` (494:570), `requests.src.requests.models.PreparedRequest:prepare_content_length` (572:586), `requests.src.requests.models.PreparedRequest:prepare_auth` (588:608), `requests.src.requests.models.PreparedRequest:prepare_cookies` (610:628), `requests.src.requests.models.PreparedRequest:prepare_hooks` (630:637)