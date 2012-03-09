# Path hack.
import sys
import os
sys.path.insert(0, os.path.abspath('..'))

import requests

"""

    HTTPS Proxy and SOCKS proxy support
    - Added 09/03/2012 by Cal Leeming (Simplicity Media Ltd)

"""

# Ensure socks5 is working
# This has been tested against 'dante-server'
proxiesDict = {
    'http' : "socks5://1.2.3.4:1080",
    'https' : "socks5://1.2.3.4:1080"
}
print requests.get("https://ipcheckit.com/", proxies = proxiesDict).content

# Ensure SSL proxy is working
# This has been tested against 'Burp Proxy'
proxiesDict = {
    'http' : "1.2.3.4:8080",
    'https' : "1.2.3.4:8080"
}
print requests.get("https://ipcheckit.com/", proxies = proxiesDict).content
