# -*- coding: utf-8 *-*
# filename: threaded_requests.py
# author: Anthony Glaser
# aka: scruffyexaminer

"""A simple module for threading requests. Two use-cases are covered: making
simple get requests and downloads."""


import threading
from .api import request
from .exceptions import Timeout


TIMEOUT_ERR = 'request timed out'
STATUS_ERR = 'status not 200'
UNKNOWN_ERR = 'unknown error'
TIMEOUT = 20


class ThreadedRequest(threading.Thread):
    """ThreadedRequest makes it easy to make an http request on a seperate
    thread of control. The thread will be a daemon thread, so when the main
    thread finishes the thread will be destroyed if it hasn't already.

    Once the threaded request has been started another thread (i.e. main) may
    check the state of the request using the bound is_requesting() method.

    The thread can be cancelled by using the bound cancel() method.

    Once the thread is no longer requesting, check the bound 'error' variable
    to make sure everything was ok. If it was ok, the bound 'r' variable should
    no longer point to None, but to a requests.Response object."""

    timeout = TIMEOUT

    def __init__(self, method, url, **kwargs):
        """The init signature is the same as for requests.request. Do not use
        the 'stream' kwarg. Use the DownloadThread class instead."""

        if 'stream' in kwargs:
            raise Exception("kwarg 'stream' not appropriate.")

        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout

        threading.Thread.__init__(self)
        self.daemon = True

        self.method = method
        self.url = url
        self.kwargs = kwargs

        self.r = None
        self.error = None
        self.cancelled = False

    def cancel(self):
        """Use to cancel a request. 'is_requesting' will return False, and
        the bound variable 'cancelled' will be set to True."""

        self.cancelled = True

    def is_requesting(self):
        """Use to check if the thread is still waiting for a response from
        the server. Once the thread has been started and this returns False,
        check the bound variables 'error', 'cancelled', and 'r' to check
        the outcome of the request."""

        return self.r is None and self.error is None and not self.cancelled

    def request_successful(self):
        """Use to check if the request finished without errors and 'r' is
        ready to use."""

        check = self.r is not None and self.error is None
        return check and not self.cancelled

    def _make_request(self, stream=False):

        try:
            self.r = request(self.method, self.url, stream=stream, **self.kwargs)
        except Timeout as e:
            self.error = TIMEOUT_ERR
        except Exception as e:
            self.error = UNKNOWN_ERR
            self.e = e

        if self.error is None and self.r.status_code != 200:
            self.error = STATUS_ERR

    def run(self):

        self._make_request()


class GetThread(ThreadedRequest):
    """As per ThreadedRequest except there is no need to specify 'GET' as
    the http contact method."""

    def __init__(self, url, **kwargs):

        ThreadedRequest.__init__(self, 'GET', url, **kwargs)


class DownloadThread(GetThread):
    """A DownloadThread is a GetThread which streams the downloading of the
    requets.Response object using r.iter_content if the binary arg is true,
    otherwise r.iter_lines. In each case the chunk size for streaming is set
    to 1/100 of r.headers['content-length']. Every chunk increases the bound
    variable r.progress by one, which can be used by another thread(i.e. main)
    to inform the user on download progress. When the thread is requesting, the
    bound method 'is_requesting' returns True and when the thread is
    downloading the bound method 'is_downloading' returns true. If the thread
    was able to download the entire stream without being cancelled or getting
    an error the bound variable 'complete' will be True. """

    @staticmethod
    def file_str(url):
        """Returns the substring of url after the last '/'."""
        return url.split(r'/')[-1]

    @staticmethod
    def download_str(file_str, mb_str=''):
        """Returns the string:        'Downloading: %file_str'
        if mb_str is given, appends:                         '(%mb_str MB)'
        """

        if mb_str:
            mb_str = ' (' + mb_str + ' MB)'
        return 'Downloading: ' + file_str + mb_str

    def __init__(self, url, binary=True, **kwargs):
        """The binary kwarg determines whether r.iter_content or r.iter_lines
        is used to stream the download. See the requests module."""

        GetThread.__init__(self, url, **kwargs)

        self.binary = binary

        self.content = ''
        self.size = None
        self.progress = 0
        self.complete = False

    def mb_str(self):
        """Returns the size of the download in MB if possible."""

        if self.request_successful():
            if self.size is None:
                self._calculate_size()
            return str(self.mb_size)
        else:
            return ''

    def is_downloading(self):
        """Returns true if the thread is alive, 'r' and 'error' are not None,
        and 'complate' is false. Once 'is_requesting' has fallen from True to
        False, is_downloading' should rise from False to True. Once it goes
        back down to False, check the bound variables 'error', 'cancelled',
        'progress', and 'complete' to see the outcome of the download. If
        'complete' is True, the downloaded data will be available with the
        bound varibale 'content'."""

        check = self.is_alive() and self.r is not None and self.error is None
        check = check and not self.complete

        return check

    def download_successful(self):
        """Returns true if downloaded completed without errors and 'content'
        variable is ready."""

        check = not self.is_requesting() and not self.is_downloading()
        check = check and self.r is not None and self.error is None
        check = not self.cancelled and self.complete

        return check

    def _calculate_size(self):

        self.size = int(self.r.headers['content-length'])
        self.mb_size = self.size / 1024 / 1024

    def _download_content(self):

        self._calculate_size()

        chunk_size = self.size / 100

        if self.binary:
            iter_fn = self.r.iter_content
        else:
            iter_fn = self.r.iter_lines

        if self.cancelled:
            return

        try:
            for buf in iter_fn(chunk_size):
                if buf:
                    self.content += buf
                    self.progress += 1
                    if self.cancelled:
                        break
            self.complete = True
        except Timeout:
            self.error = TIMEOUT_ERR
        except Exception:
            self.error = UNKNOWN_ERR

    def run(self):
        self._make_request(stream=True)
        if not self.request_successful():
            return
        self._download_content()
