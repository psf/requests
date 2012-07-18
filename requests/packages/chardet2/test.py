from __future__ import print_function
import sys, glob
sys.path.insert(0, '..')
from chardet.universaldetector import UniversalDetector

count = 0
u = UniversalDetector()
for f in glob.glob(sys.argv[1]):
    print(f.ljust(60), end=' ')
    u.reset()
    for line in open(f, 'rb'):
        u.feed(line)
        if u.done: break
    u.close()
    result = u.result
    if result['encoding']:
        print(result['encoding'], 'with confidence', result['confidence'])
    else:
        print('******** no result')
    count += 1
print(count, 'tests')
