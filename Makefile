SHELL := /bin/bash

init:
	python setup.py develop
	pip install -r requirements.txt

test:
	nosetests ./tests/*

lazy:
	nosetests --with-color tests/test_requests.py

simple:
	nosetests tests/test_requests.py

server:
	gunicorn httpbin:app --bind=0.0.0.0:7077 &

ci: init
	nosetests tests/test_requests.py --with-xunit --xunit-file=junit-report.xml

simpleci:
	nosetests tests/test_requests.py --with-xunit --xunit-file=junit-report.xml

stats:
	pyflakes requesocks | awk -F\: '{printf "%s:%s: [E]%s\n", $1, $2, $3}' > violations.pyflakes.txt

site:
	cd docs; make dirhtml

pyc:
	find . -name "*.pyc" -exec rm '{}' ';'

deps:
	rm -fr requesocks/packages/urllib3
	git clone https://github.com/shazow/urllib3.git
	cd urllib3 && git checkout release && cd ..
	mv urllib3/urllib3 requesocks/packages/
	rm -fr urllib3

docs: site
