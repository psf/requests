import requests


def uc_unicom(ip):
    try:
        headers = {
            'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36 Edg/111.0.1661.41'
        }
        proxies = {
            'http': f'http://{ip}',
            'https': f'http://{ip}',
            'headers': {
                'Proxy-Authorization': 'Basic dXNlcjpwd2Q='
            }
        }
        response = requests.get('https://api.ip.sb/ip', headers=headers, proxies=proxies)
        print(response.text)
    except Exception as e:
        print(e)



if __name__ == '__main__':
    uc_unicom('127.0.0.1:8080')
