# urllib3/exceptions.py
# Copyright 2008-2012 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php


## Base Exceptions

class HTTPError(Exception):
    "Base exception used by this module."
    pass


class PoolError(HTTPError):
    "Base exception for errors caused within a pool."
    def __init__(self, pool, message):
        self.pool = pool
        HTTPError.__init__(self, "%s: %s" % (pool, message))

    def __reduce__(self):
        # For pickling purposes.
        return self.__class__, (None, self.url)


class SSLError(HTTPError):
    "Raised when SSL certificate fails in an HTTPS connection."
    pass


class DecodeError(HTTPError):
    "Raised when automatic decoding based on Content-Type fails."
    pass


## Leaf Exceptions

class MaxRetryError(PoolError):
    "Raised when the maximum number of retries is exceeded."

    def __init__(self, pool, url, reason=None):
        self.reason = reason

        message = "Max retries exceeded with url: %s" % url
        if reason:
            message += " (Caused by %s: %s)" % (type(reason), reason)
        else:
            message += " (Caused by redirect)"

        PoolError.__init__(self, pool, message)
        self.url = url


class HostChangedError(PoolError):
    "Raised when an existing pool gets a request for a foreign host."

    def __init__(self, pool, url, retries=3):
        message = "Tried to open a foreign host with url: %s" % url
        PoolError.__init__(self, pool, message)

        self.url = url
        self.retries = retries


class TimeoutError(PoolError):
    "Raised when a socket timeout occurs."
    pass


class EmptyPoolError(PoolError):
    "Raised when a pool runs out of connections and no more are allowed."
    pass


class ClosedPoolError(PoolError):
    "Raised when a request enters a pool after the pool has been closed."
    pass


class LocationParseError(ValueError, HTTPError):
    "Raised when get_host or similar fails to parse the URL input."

    def __init__(self, location):
        message = "Failed to parse: %s" % location
        HTTPError.__init__(self, message)

        self.location = location
