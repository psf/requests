nosetests test_requests.py --with-xunit --with-coverage 
coverage xml
rm -fr pylint.txt
pylint -d W0312 -d W0212 -d E1101 -d E0202 -d W0102 -d E0102 -f parseable ./requests > pylint.txt || true
