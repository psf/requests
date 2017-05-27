import sys

# This code exists for backwards compatibility reasons.
# I don't like it either. Just look the other way. :)

import urllib3
sys.modules['requests.packages.urllib3'] = urllib3

import idna
sys.modules['requests.packages.idna'] = idna

import chardet
sys.modules['requests.packages.chardet'] = chardet

# Kinda cool, though, right?