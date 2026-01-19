import requests


def test_cookie_allows_empty_string_value():
    jar = requests.cookies.RequestsCookieJar()
    jar.set("empty", "")
    assert jar.get("empty") == ""


def test_cookie_allows_zero_value():
    jar = requests.cookies.RequestsCookieJar()
    jar.set("zero", 0)
    assert jar.get("zero") == 0
