# urllib3/httpconnection.py
# Copyright 2008-2012 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php

try: # Python 3
    from http.client import HTTPConnection, HTTPException
    from http.client import HTTP_PORT, HTTPS_PORT
except ImportError:
    from httplib import HTTPConnection, HTTPException
    from httplib import HTTP_PORT, HTTPS_PORT

class SkipFriendlyHTTPConnection(HTTPConnection):
    def request(self, method, url, body=None, skip_host=False, skip_accept_encoding=False, headers={}):
        """Send a complete request to the server."""
        self._send_request(method, url, body, headers, skip_host=skip_host, skip_accept_encoding=skip_accept_encoding)

    def _send_request(self, method, url, body, headers, skip_host=False, skip_accept_encoding=False):
        header_names = dict.fromkeys([k.lower() for k in headers])
        skips = {}
        # enable skip_host and skip_accept_encoding from py2.4
        if skip_host or ('host' in header_names):
            skips['skip_host'] = 1
        if skip_accept_encoding or ('accept-encoding' in header_names):
            skips['skip_accept_encoding'] = 1

        self.putrequest(method, url, **skips)

        if body is not None and ('content-length' not in header_names):
            self._set_content_length(body)
        for hdr, value in headers.items():
            self.putheader(hdr, value)
        if isinstance(body, str):
            # RFC 2616 Section 3.7.1 says that text default has a
            # default charset of iso-8859-1.
            body = body.encode('iso-8859-1')
        self.endheaders(body)
HTTPConnection = SkipFriendlyHTTPConnection

try: # Compiled with SSL?
    try: # Python 3
        from http.client import HTTPSConnection
    except ImportError:
        from httplib import HTTPSConnection

    class SkipFriendlyHTTPSConnection(SkipFriendlyHTTPConnection): pass
    HTTPSConnection = SkipFriendlyHTTPSConnection
except (ImportError, AttributeError):
    pass
