
#file: test_threaded_requests.py

#One day I'll learn about unit testing.

import requests.threaded_requests as threaded_requests
from requests import GetThread, DownloadThread

import time

get_url = r'http://www.example.com'
dwnld_url = r'http://upload.wikimedia.org/wikipedia/commons/'
dwnld_url = dwnld_url + r'0/0c/Moon_transit_of_sun_large.ogg'

def _make_args(url, corrupt_url, corrupt_proxy):

    if corrupt_url:
        url = 'http://www.arcdsrabk2352309.com'

    if corrupt_proxy:
        proxies = {'http': 'www.example.com'}
    else:
        proxies = None

    return url, proxies

def test_getthread(corrupt_url=False, corrupt_proxy=False, timeout=20,
                        cancel=False):
    """Use to test GetThread."""

    url, proxies = _make_args(get_url, corrupt_url, corrupt_proxy)

    getthread = GetThread(url, proxies=proxies, timeout=timeout)

    print '-' * 50
    print 'GetThread Test:'
    print '\turl: ' + getthread.url
    print '\tproxies: ' + str(getthread.kwargs['proxies'])

    getthread.start()

    while getthread.is_requesting():
        print '.',
        time.sleep(.05)
        if cancel:
            getthread.cancel()

    print

    if getthread.request_successful():
        print '\tStatus: ' + str(getthread.r.status_code)
        print '\tContent-Length: ' + getthread.r.headers['content-length']
    else:
        print '\tError: ' + str(getthread.error)
        if getthread.error == threaded_requests.UNKNOWN_ERR:
            print getthread.e
        if getthread.cancelled:
            print 'Cancelled.'

def make_downloadthread(corrupt_url=False, corrupt_proxy=False, timeout=20):
    """Use to make Download objs for testing with test_download."""

    url, proxies = _make_args(dwnld_url, corrupt_url, corrupt_proxy)

    return DownloadThread(url, proxies=proxies, timeout=timeout)

def test_downloadthread(dwnld, cancel=False):
    """Use to test download objects."""

    print '-' * 50
    print 'Download Test:'
    print '\turl: ' + dwnld.url
    print '\tproxies=' + str(dwnld.kwargs['proxies'])

    dwnld.start()

    while dwnld.is_requesting():
        print '.',
        time.sleep(.05)

    print

    if dwnld.request_successful():
        print '\tStatus: ' + str(dwnld.r.status_code)
        file_str = DownloadThread.file_str(dwnld.url)
        print DownloadThread.download_str(file_str, dwnld.mb_str())
    else:
        print str(dwnld.error)
        return

    while dwnld.is_downloading():
        time.sleep(0.5)
        print dwnld.progress,
        if dwnld.progress > 20 and cancel:
            dwnld.cancel()

    print

    if dwnld.download_successful():
        print '\tdata len: ' + str(len(dwnld.content))
    else:
        print '\tError: ' + str(dwnld.error)
        if dwnld.error == threaded_requests.UNKNOWN_ERR:
            print dwnld.e
        if dwnld.cancelled:
            print 'Cancelled.'

if __name__ == '__main__':

    import os
    import webbrowser

    test_getthread()
    test_getthread(corrupt_url=True)
    test_getthread(corrupt_proxy=True)
    test_getthread(timeout=0.0001)
    test_getthread(cancel=True)

    dwnld = make_downloadthread()
    test_downloadthread(dwnld, cancel=True)
    dwnld = make_downloadthread()
    test_downloadthread(dwnld)

    if dwnld.download_successful():
        filename = DownloadThread.file_str(dwnld_url)
        with open(filename, 'wb') as f:
            f.write(dwnld.content)
        webbrowser.open(filename)
