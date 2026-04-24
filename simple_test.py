import requests
import time

# Test gzip streaming
url = 'https://httpbin.org/gzip'
r = requests.get(url, stream=True)
print(f"Status code: {r.status_code}")
print(f"Content-Encoding: {r.headers.get('Content-Encoding')}")

content = b''
chunk_count = 0

for chunk in r.iter_content(chunk_size=128):
    if chunk:
        chunk_count += 1
        content += chunk
        print(f"Chunk {chunk_count}: {len(chunk)} bytes")

print(f"Total chunks: {chunk_count}")
print(f"Total content length: {len(content)} bytes")
print(f"Content preview: {content[:100]}")