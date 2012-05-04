import gc, os, subprocess, requests

gc.disable()         # Just to make sure - I have seen this with gc enabled

for x in range(20):
    requests.head("http://www.google.com/")

print "Open sockets after 20 head requests:"
pid = os.getpid()
subprocess.call("lsof -p%d -a -iTCP" % (pid,), shell=True)

gcresult = gc.collect()
print "Garbage collection result: %s" % (gcresult,)

print "Open sockets after garbage collection:"
subprocess.call("lsof -p%d -a -iTCP" % (pid,), shell=True)
