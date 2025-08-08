from requests.cookies import RequestsCookieJar

def test_cookiejar_allows_empty_and_zero_values():
    jar = RequestsCookieJar()
    jar.set('empty', '', domain='example.com')
    assert jar.get('empty') == ''
    jar.set('zero', 0, domain='example.com')
    # Requests stores values as strings
    assert jar.get('zero') == '0'
