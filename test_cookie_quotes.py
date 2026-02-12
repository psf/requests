import requests
from requests.cookies import create_cookie

def cookie_escaped_quotes():
    cookie = create_cookie(
        name="test_cookie",
        value='"159\\"687"',  
        domain="example.com"
    )

    with requests.Session() as s:
        s.cookies.set_cookie(cookie)
        retrieved = s.cookies.get("test_cookie")
        print(f'Expected: 159\\"687 | Actual: {retrieved}')


def cookie_no_quotes():
    cookie = create_cookie(
        name="test_cookie",
        value='159\\"687', 
        domain="example.com"
    )

    with requests.Session() as s:
        s.cookies.set_cookie(cookie)
        retrieved = s.cookies.get("test_cookie")
        print(f'Expected: 159\\"687 | Actual: {retrieved}')  

def cookie_no_escaped_quotes():
    cookie = create_cookie(
        name="test_cookie",
        value='159\\687', 
        domain="example.com"
    )

    with requests.Session() as s:
        s.cookies.set_cookie(cookie)
        retrieved = s.cookies.get("test_cookie")
        print(f'Expected: 159\\687 | Actual: {retrieved}')  

def cookie_json_fragment():
    cookie = create_cookie(
        name="session_data",
        value='"{\\"user\\": \\"x\\", \\"id\\": 42}"',  
        domain="example.com"
    )

    with requests.Session() as s:
        s.cookies.set_cookie(cookie)
        retrieved = s.cookies.get("session_data")
        print(f'Expected: {{"user": "x", "id": 42}} | Actual: {retrieved}')

cookie_escaped_quotes()
cookie_no_quotes()
cookie_no_escaped_quotes()