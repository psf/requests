SHELL := /bin/bash

test:
	py.test

test-deps:
	pip install -r requirements.txt

six:
	python test_requests.py
	python3 test_requests.py

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