import sys, glob
from io import open
sys.path.insert(0, u'..')
from chardet.universaldetector import UniversalDetector

count = 0
u = UniversalDetector()
for f in glob.glob(sys.argv[1]):
    print f.ljust(60),
    u.reset()
    for line in open(f, u'rb'):
        u.feed(line)
        if u.done: break
    u.close()
    result = u.result
    if result[u'encoding']:
        print result[u'encoding'], u'with confidence', result[u'confidence']
    else:
        print u'******** no result'
    count += 1
print count, u'tests'
