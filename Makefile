SHELL := /bin/bash

# these files should pass pyflakes
# exclude ./env/, which may contain virtualenv packages
PYFLAKES_WHITELIST=$(shell find . -name "*.py" ! -path "./docs/*" ! -path "./tests/*" \
	! -path "./requests/packages/*" ! -path "./env/*" \
	! -path "./requests/__init__.py" ! -path "./requests/compat.py")

# hack: if pyflakes is available, set this to the location of pyflakes
# if it's not, e.g., in the Python 3 or PyPy Jenkins environments, set it to
# the location of the no-op `true` command.
PYFLAKES_IF_AVAILABLE=$(shell if which pyflakes > /dev/null ; \
	then which pyflakes; \
	else which true; fi )

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

cipyflakes:
	${PYFLAKES_IF_AVAILABLE} ${PYFLAKES_WHITELIST}

citests:
	nosetests ${CI_TESTS} --with-xunit --xunit-file=junit-report.xml

ci: citests cipyflakes

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

deps: urllib3 certs

urllib3:
	rm -fr requests/packages/urllib3
	git clone https://github.com/shazow/urllib3.git
	cd urllib3 && git checkout master && cd ..
	mv urllib3/urllib3 requests/packages/
	rm -fr urllib3

oauthlib:
	rm -fr requests/packages/oauthlib
	git clone https://github.com/idan/oauthlib.git
	cd oauthlib && git checkout master && cd ..
	mv oauthlib/oauthlib requests/packages/
	rm -fr oauthlib

certs:
	cd requests && curl -O https://raw.github.com/kennethreitz/certifi/master/certifi/cacert.pem

docs: site
