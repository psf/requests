SHELL := /bin/bash

# test_requests_ext.py depends on external services, and async doesn't work under Python 3
# Travis/Jenkins should be ensuring that all other tests pass on all supported versions
CI_TESTS=$(shell find tests/ -name "*.py" ! -name "test_requests_ext.py" ! -name "test_requests_async.py")

iter:
	python test_iteration.py

init:
	python setup.py develop
	pip install -r requirements.txt

test:
	nosetests ./tests/*

lazy:
	nosetests --with-color tests/test_requests.py

simple:
	nosetests tests/test_requests.py

citests:
	nosetests ${CI_TESTS} --with-xunit --xunit-file=junit-report.xml

ci: citests cipyflakes

travis: citests

server:
	gunicorn httpbin:app --bind=0.0.0.0:7077 &

deps: urllib3 certs charade

urllib3:
	rm -fr requests/packages/urllib3
	git clone https://github.com/shazow/urllib3.git
	cd urllib3 && git checkout master && cd ..
	mv urllib3/urllib3 requests/packages/
	rm -fr urllib3

charade:
	rm -fr requests/packages/charade
	git clone https://github.com/sigmavirus24/charade.git
	cd charade && git checkout master && cd ..
	mv charade/charade requests/packages/
	rm -fr charade

certs:
	cd requests && curl -O https://raw.github.com/kennethreitz/certifi/master/certifi/cacert.pem

docs: site
