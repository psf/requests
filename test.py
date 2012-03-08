import requests

s = requests.session()
s.config['encode_urls'] = False

r = s.get('http://localhost:7077/get?me=\"')
print r.text
