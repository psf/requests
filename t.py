from requests.packages import chardet

with open('test', 'rb') as f:
    print(chardet.detect(f.read()))