# urllib3/exceptions.py
# Copyright 2008-2011 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php

## Exceptions

class HTTPError(Exception):
    "Base exception used by this module."
    pass


class SSLError(Exception):
    "Raised when SSL certificate fails in an HTTPS connection."
    pass


class MaxRetryError(HTTPError):
    "Raised when the maximum number of retries is exceeded."
    def __init__(self, url):
        HTTPError.__init__(self, "Max retries exceeded for url: %s" % url)
        self.url = url


class TimeoutError(HTTPError):
    "Raised when a socket timeout occurs."
    pass


class HostChangedError(HTTPError):
    "Raised when an existing pool gets a request for a foreign host."
    def __init__(self, original_host, new_url, retries=3):
        HTTPError.__init__(self,
            "Connection pool with host '%s' tried to open a foreign host: %s" %
            (original_host, new_url))

        self.original_host = original_host
        self.new_url = new_url
        self.retries = retries


class EmptyPoolError(HTTPError):
    "Raised when a pool runs out of connections and no more are allowed."
    pass
