"""
This is an informal test originally written by Bluehorn;
it verifies that Requests does not leak connections when
the body of the request is not read.
"""

import gc, os, subprocess, requests, sys

def main():
    gc.disable()

    for x in range(20):
        requests.head("http://www.google.com/")

    print("Open sockets after 20 head requests:")
    pid = os.getpid()
    subprocess.call("lsof -p%d -a -iTCP" % (pid,), shell=True)

    gcresult = gc.collect()
    print("Garbage collection result: %s" % (gcresult,))

    print("Open sockets after garbage collection:")
    subprocess.call("lsof -p%d -a -iTCP" % (pid,), shell=True)

if __name__ == '__main__':
    sys.exit(main())
