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

ci:
	find tests/ -name "*.py" ! -path "test_requests_ext.py" | xargs nosetests --with-xunit --xunit-file=junit-report.xml

server:
	gunicorn httpbin:app --bind=0.0.0.0:7077 &

stats:
	pyflakes requests | awk -F\: '{printf "%s:%s: [E]%s\n", $1, $2, $3}' > violations.pyflakes.txt

site:
	cd docs; make dirhtml

pyc:
	find . -name "*.pyc" -exec rm '{}' ';'

deps:
	rm -fr requests/packages/urllib3
	git clone https://github.com/shazow/urllib3.git
	cd urllib3 && git checkout master && cd ..
	mv urllib3/urllib3 requests/packages/
	rm -fr urllib3

docs: site
