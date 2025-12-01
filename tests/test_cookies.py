from my_requests.cookies import RequestsCookieJar


def test_cookie_empty_value_bug():
    jar = RequestsCookieJar()
    jar.set('token', 0, domain='example.com', path='/')

    assert list(jar.items()) == [('token', 0)]
    assert jar.get('token', domain='example.com', path='/') == 0


def test_cookie_zero_value_among_others():
    jar = RequestsCookieJar()
    jar.set('token', 0, domain='example.com', path='/')
    jar.set('session', 'abc', domain='example.com', path='/')

    assert jar.get('token', domain='example.com', path='/') == 0


def test_cookie_string_zero_value():
    jar = RequestsCookieJar()
    jar.set('code', '0', domain='example.com', path='/')

    assert jar.get('code', domain='example.com', path='/') == '0'


def test_cookie_empty_string_value():
    jar = RequestsCookieJar()
    jar.set('empty', '', domain='example.com', path='/')

    assert jar.get('empty', domain='example.com', path='/') == ''


def test_cookie_none_value():
    jar = RequestsCookieJar()
    jar.set('missing', None, domain='example.com', path='/')

    assert jar.get('missing', domain='example.com', path='/') is None


def test_cookie_zero_value_with_domain_and_path_matching():
    jar = RequestsCookieJar()
    jar.set('token', 0, domain='example.com', path='/api')

    assert jar.get('token', domain='example.com', path='/api') == 0


def test_cookie_overwrite_zero_value():
    jar = RequestsCookieJar()
    jar.set('token', 'old', domain='example.com', path='/')
    jar.set('token', 0, domain='example.com', path='/')

    assert jar.get('token', domain='example.com', path='/') == 0


def test_cookie_zero_value_persists_after_update():
    jar = RequestsCookieJar()
    jar.set('token', 0, domain='example.com', path='/')

    jar.update(jar)

    assert jar.get('token', domain='example.com', path='/') == 0
