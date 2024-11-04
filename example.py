import requests

def fetch_github_api():
    response = requests.get('https://api.github.com')
    print(response.status_code)  # Should print 200 if successful
    print(response.json())       # Prints the JSON content of the response

if __name__ == "__main__":
    fetch_github_api()
