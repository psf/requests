"""
urllib3 - Thread-safe connection pooling and re-using.
"""

from connectionpool import (
    connection_from_url,
    get_host,
    HTTPConnectionPool,
    HTTPSConnectionPool,
    make_headers)
# Possible exceptions
from connectionpool import (
    HTTPError,
    MaxRetryError,
    SSLError,
    TimeoutError)
from filepost import encode_multipart_formdata


__author__ = "Andrey Petrov (andrey.petrov@shazow.net)"
__license__ = "MIT"
__version__ = "$Rev$"
