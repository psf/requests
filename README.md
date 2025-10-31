# Requests

**Requests** is a simple, yet elegant, HTTP library for Python, making HTTP requests incredibly straightforward.

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

---

## 🚀 Quick Start

### Installation
Requests is available on PyPI and can be installed via pip:

```bash
pip install requests
```

Supported Python versions: 3.9+

### Verify Installation

```python
import requests
print(f"Requests version: {requests.__version__}")
```

---

## 💡 Common Usage Examples

### Basic GET Request

```python
import requests

# Simple GET request
response = requests.get('https://api.github.com')
print(f"Status Code: {response.status_code}")
print(f"Headers: {response.headers['content-type']}")

# Access JSON data
data = response.json()
print(f"GitHub API Rate Limit: {data['resources']['core']['limit']}")
```

### POST Request with JSON Data

```python
import requests

# POST with JSON data
payload = {'name': 'John', 'email': 'john@example.com'}
response = requests.post('https://httpbin.org/post', json=payload)

print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")
```

### Handling Authentication

```python
import requests
from requests.auth import HTTPBasicAuth

# Basic Authentication
response = requests.get(
    'https://httpbin.org/basic-auth/user/pass',
    auth=HTTPBasicAuth('user', 'pass')
)

# Or simpler:
response = requests.get(
    'https://httpbin.org/basic-auth/user/pass',
    auth=('user', 'pass')
)
```

### Working with Query Parameters

```python
import requests

# Automatic query parameter handling
params = {'search': 'python', 'page': 1, 'limit': 10}
response = requests.get('https://httpbin.org/get', params=params)

print(f"URL: {response.url}")
print(f"Params: {response.json()['args']}")
```

---

## 🛠️ Advanced Features

### Session Management

```python
import requests

# Use sessions for connection pooling and cookie persistence
with requests.Session() as session:
    session.headers.update({'User-Agent': 'MyApp/1.0'})
    
    # All requests in this session share cookies and connections
    response1 = session.get('https://httpbin.org/cookies/set/sessioncookie/123456789')
    response2 = session.get('https://httpbin.org/cookies')
    
    print(f"Cookies: {response2.json()}")
```

### File Upload

```python
import requests

# Upload a file
files = {'file': open('report.pdf', 'rb')}
response = requests.post('https://httpbin.org/post', files=files)

# Upload with additional data
files = {'file': ('report.pdf', open('report.pdf', 'rb'), 'application/pdf')}
data = {'description': 'Quarterly report'}
response = requests.post('https://httpbin.org/post', files=files, data=data)
```

### Streaming Large Responses

```python
import requests

# Stream large responses to avoid loading everything into memory
response = requests.get('https://httpbin.org/stream/100', stream=True)

for line in response.iter_lines():
    if line:
        print(f"Received: {line.decode('utf-8')}")
```

---

## 🐛 Troubleshooting Common Issues

### Handling Errors Gracefully

```python
import requests
from requests.exceptions import RequestException

try:
    response = requests.get('https://httpbin.org/status/404', timeout=5)
    response.raise_for_status()  # Raises an HTTPError for bad responses
except requests.exceptions.HTTPError as http_err:
    print(f'HTTP error occurred: {http_err}')
except requests.exceptions.ConnectionError as conn_err:
    print(f'Connection error occurred: {conn_err}')
except requests.exceptions.Timeout as timeout_err:
    print(f'Timeout error occurred: {timeout_err}')
except requests.exceptions.RequestException as req_err:
    print(f'An error occurred: {req_err}')
```

### SSL Certificate Verification

```python
import requests

# For self-signed certificates (development only)
response = requests.get('https://self-signed-example.com', verify=False)

# Or specify a custom CA bundle
response = requests.get('https://example.com', verify='/path/to/certfile.pem')
```

### Setting Timeouts

```python
import requests

# Always set timeouts to avoid hanging requests
try:
    response = requests.get('https://httpbin.org/delay/10', timeout=3.5)
except requests.exceptions.Timeout:
    print("Request timed out!")
```

---

## 📊 Supported Features

Requests is ready for building robust HTTP applications with:

✅ Keep-Alive & Connection Pooling - Efficient connection reuse  
✅ International Domains and URLs - Full Unicode support  
✅ Sessions with Cookie Persistence - Maintain state across requests  
✅ Browser-style TLS/SSL Verification - Secure by default  
✅ Basic & Digest Authentication - Multiple auth methods  
✅ Automatic Content Decompression - gzip, deflate compression  
✅ Streaming Downloads - Handle large responses efficiently  
✅ SOCKS Proxy Support - Complete proxy support  
✅ Connection Timeouts - Prevent hanging requests  
✅ Chunked HTTP Requests - Efficient large uploads  

---

## 🔧 Installation Options

### Using conda

```bash
conda install -c anaconda requests
```

### From Source

```bash
git clone https://github.com/psf/requests.git
cd requests
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/psf/requests.git
cd requests
pip install -e ".[socks]"  # With optional SOCKS support
pip install -r requirements-dev.txt  # Development dependencies
```

---

## 📚 Documentation

Complete API reference and user guide available on [Read the Docs](https://requests.readthedocs.io).

![Requests Example](https://raw.githubusercontent.com/psf/requests/main/ext/ss.png)

---

## 🤝 Contributing

We welcome contributions! Please see our Contributing Guide for details.

### Cloning the Repository

```bash
git clone -c fetch.fsck.badTimezone=ignore https://github.com/psf/requests.git
```

Or set globally:

```bash
git config --global fetch.fsck.badTimezone ignore
```

---

## 📈 Project Stats

![Downloads](https://static.pepy.tech/badge/requests/month)
![Python Versions](https://img.shields.io/pypi/pyversions/requests.svg)
![Contributors](https://img.shields.io/github/contributors/psf/requests.svg)

Requests is one of the most downloaded Python packages with over **30 million downloads per week** and trusted by **1,000,000+ repositories**.

![PSF](https://raw.githubusercontent.com/psf/requests/main/ext/psf.png)

---

## 🛠️ EXACT STEPS TO APPLY

1. Open `README.md`
2. Select ALL (Ctrl+A) and DELETE everything
3. COPY this improved version and PASTE it into the file
4. SAVE (Ctrl+S)

---

## 🚀 THEN COMMIT & PUSH

```bash
git checkout -b docs/improve-readme-examples
git add README.md
git commit -m "docs: completely rewrite README with comprehensive examples and troubleshooting guide"
git push origin docs/improve-readme-examples
```
