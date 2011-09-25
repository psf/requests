## Exceptions

class HTTPError(Exception):
    "Base exception used by this module."
    pass


class SSLError(Exception):
    "Raised when SSL certificate fails in an HTTPS connection."
    pass


class MaxRetryError(HTTPError):
    "Raised when the maximum number of retries is exceeded."
    pass


class TimeoutError(HTTPError):
    "Raised when a socket timeout occurs."
    pass


class HostChangedError(HTTPError):
    "Raised when an existing pool gets a request for a foreign host."
    pass

class EmptyPoolError(HTTPError):
    "Raised when a pool runs out of connections and no more are allowed."
    pass
