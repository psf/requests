from requests.cookies import RequestsCookieJar


def test_cookiejar_zero_value():
    jar = RequestsCookieJar()
    jar.set('token', 0, domain='example.com', path='/')

    assert ('token', 0) in jar.items()
    assert jar.get('token', domain='example.com', path='/') == 0
    assert jar['token'] == 0
