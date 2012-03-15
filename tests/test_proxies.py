#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Path hack.
import sys, os
sys.path.insert(0, os.path.abspath('..'))

import requests

"""

    HTTPS Proxy and SOCKS proxy support
    - Added 09/03/2012 by Cal Leeming (Simplicity Media Ltd)

"""

# Ensure socks5 is working
# This has been tested against 'dante-server'
proxiesDict = {
    'http' : "socks5://127.0.0.1:1080",
    'https' : "socks5://127.0.0.1:1080"
}
print "HTTPS via SOCKS5"
print "------------------------------------------------------------"
print requests.get("https://ipcheckit.com/", proxies = proxiesDict).content
print ""

print "HTTP via SOCKS5"
print "------------------------------------------------------------"
print requests.get("http://ipcheckit.com/", proxies = proxiesDict).content
print ""

# Ensure SSL proxy is working
# This has been tested against 'Burp Proxy'
proxiesDict = {
    'http' : "127.0.0.1:8080",
    'https' : "127.0.0.1:8080"
}
print "HTTPS via HTTP Proxy"
print "------------------------------------------------------------"
print requests.get("https://ipcheckit.com/", proxies = proxiesDict).content
print ""

print "HTTP via HTTP Proxy"
print "------------------------------------------------------------"
print requests.get("http://ipcheckit.com/", proxies = proxiesDict).content
print ""


print "HTTPS via no proxy"
print "------------------------------------------------------------"
print requests.get("https://ipcheckit.com/").content
print ""

print "HTTP via no proxy"
print "------------------------------------------------------------"
print requests.get("http://ipcheckit.com/").content
print ""
