import argparse
import os
import re
from . import api

def filename(request) :  
#   print(request.headers)
  try : 
    filedata   = request.headers.get("content-disposition")
    filename = os.pathsep.join(re.findall('filename=(.+)', filedata))
  except : 
    filename = os.pathsep.join(request.url.rsplit('/', 1)[1])
  finally :
    return filename

def download(args) :
  # NOTE the stream=True parameter below
  with api.get(args.url, stream=True) as request:
    request.raise_for_status()
    with open(args.filename or filename(request), 'wb') as file:
      for chunk in request.iter_content(chunk_size=1024): # 8192 ?
        if chunk: # filter out keep-alive new chunks
          file.write(chunk)
          # f.flush()
  # Initial Attempt with Requests
#   request = api.head(args.url) # , allow_redirects=args.redirect)
#   if request.headers.get('content-type').startswith("text") :
#    request = api.get(args.url,stream=True) # , allow_redirects=redirect)
#    with open(args.filename or filename(request), 'wt') as file : 
#     for chunk in request.iter_content(chunk_size=1024 or args.chunk_size):
#      if chunk : file.write(chunk)
#   else : 
#    request = api.get(args.url,stream=True) # , allow_redirects=redirect)
#    with open(args.filename or filename(request), 'wb') as file : 
#     for chunk in request.iter_content(chunk_size=1024 or args.chunk_size):
#      if chunk : file.write(chunk)
  # Backup version
# try:
#     from urllib.request import urlretrieve
# except ImportError:
#     from urllib import urlretrieve
#   urlretrieve(args.url, args.filename or filename(request))

parser  = argparse.ArgumentParser(description="Retrieve a file from the internet usign Pythons' Requests package")
parsers = parser.add_subparsers()

get  = parsers.add_parser('download')
get.add_argument('url', type=str)
get.add_argument('filename', nargs='?')
get.set_defaults(func=download)

get  = parsers.add_parser('get')
get.add_argument('url', type=str)
get.set_defaults(func=lambda args : api.get(args.url))  # Probably should print the request as a json string or something

head = parsers.add_parser('head')
head.add_argument('url', type=str)
head.set_defaults(func=lambda args : api.head(args.url)) # Probably should print the header as a json string or something

args = parser.parse_args()
args.func(args)
