import requests

r = requests.get('http://readability.com')
r.encoding = None

print(r.text)