SHELL := /bin/bash

init:
	python setup.py develop
	pip install -r requirements-dev.txt
	# install libevent first
	# 	brew install libevent
	# 	apt-get install libevent-dev
	pip install -r requirements-async.txt
	pip install -r requirements.txt

test:
	nosetests -s --with-color test_requests.py
	nosetests -s --with-color test_requests_ext.py
	nosetests -s --with-color test_requests_async.py


test-2.5:
	nosetests-2.5 --with-color test_requests.py
	nosetests-2.5 --with-color test_requests_ext.py
	nosetests-2.5 --with-color test_requests_async.py


test-jython:
	jython-nosetests --with-color test_requests.py
	jython-nosetests --with-color test_requests_ext.py
	jython-nosetests --with-color test_requests_async.py


test-jython-debug:
	jython-nosetests -s --with-color test_requests.py
	jython-nosetests -s --with-color test_requests_ext.py
	jython-nosetests -s --with-color test_requests_async.py


lazy:
	nosetests --with-color test_requests.py

server:
	gunicorn httpbin:app --bind=0.0.0.0:7077 &

ci: init
	nosetests --with-xunit --xunit-file=junit-report.xml

stats:
	pyflakes requests | awk -F\: '{printf "%s:%s: [E]%s\n", $1, $2, $3}' > violations.pyflakes.txt

site:
	cd docs; make dirhtml

pyc:
	find . -name '*.pyc' -exec rm '{}' ';'
	find . -name '*.class' -exec rm '{}' ';'


deps:
	rm -fr requests/packages/urllib3
	git clone https://github.com/shazow/urllib3.git
	cd urllib3 && git checkout python3 && cd ..
	mv urllib3/urllib3 requests/packages/
	rm -fr urllib3

docs: site
