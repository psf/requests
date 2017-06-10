import requests


def test_can_access_urllib3_attribute():
    requests.packages.urllib3


def test_can_access_idna_attribute():
    requests.packages.idna


def test_can_access_chardet_attribute():
    requests.packages.chardet
