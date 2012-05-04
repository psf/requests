SHELL := /bin/bash

# these files should pass pyflakes
# exclude ./env/, which may contain virtualenv packages
PYFLAKES_WHITELIST=$(shell find . -name "*.py" ! -path "./docs/*" ! -path "./tests/*" \
	! -path "./requests/packages/*" ! -path "./env/*" \
	! -path "./requests/__init__.py" ! -path "./requests/compat.py")

# test_requests_ext.py depends on external services, and async doesn't work under Python 3
# Travis/Jenkins should be ensuring that all other tests pass on all supported versions
CI_TESTS=$(shell find tests/ -name "*.py" ! -name "test_requests_ext.py" ! -name "test_requests_async.py")

init:
	python setup.py develop
	pip install -r requirements.txt

test:
	nosetests ./tests/*

lazy:
	nosetests --with-color tests/test_requests.py

simple:
	nosetests tests/test_requests.py

pyflakes:
	pyflakes ${PYFLAKES_WHITELIST}

citests:
	nosetests ${CI_TESTS} --with-xunit --xunit-file=junit-report.xml

ci: citests pyflakes

travis: citests

server:
	gunicorn httpbin:app --bind=0.0.0.0:7077 &

# compute statistics of various kinds
lemonade:
	-pyflakes requests > violations.pyflakes.txt
	# HTML output will be available in the default location, ./cover/
	nosetests --with-coverage --cover-html --cover-package=requests ${CI_TESTS} ./tests/test_requests_async.py

site:
	cd docs; make dirhtml

clean:
	git clean -Xfd

deps:
	rm -fr requests/packages/urllib3
	git clone https://github.com/shazow/urllib3.git
	cd urllib3 && git checkout master && cd ..
	mv urllib3/urllib3 requests/packages/
	rm -fr urllib3

docs: site
