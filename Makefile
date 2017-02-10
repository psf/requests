.PHONY: docs

init:
	pip install pipenv
	pipenv lock
	pipenv install --dev

test:
	# This runs all of the tests. To run an individual test, run py.test with
	# the -k flag, like "py.test -k test_path_is_not_double_encoded"
	pipenv run py.test tests

coverage:
	pipenv run py.test --cov-config .coveragerc --verbose --cov-report term --cov-report xml --cov=requests tests

certs:
	curl http://ci.kennethreitz.org/job/ca-bundle/lastSuccessfulBuild/artifact/cacerts.pem -o requests/cacert.pem

deps: urllib3 chardet idna

urllib3:
	git clone -b release https://github.com/shazow/urllib3.git && \
	    rm -fr requests/packages/urllib3 && \
	    cd urllib3 && \
	    git checkout `git describe --abbrev=0 --tags` && \
	    cd .. && \
	    mv urllib3/urllib3 requests/packages/ \
	    && rm -fr urllib3

chardet:
	git clone https://github.com/chardet/chardet.git && \
	    rm -fr requests/packages/chardet && \
	    cd chardet && \
	    git checkout `git describe --abbrev=0 --tags` && \
	    cd .. && \
	    mv chardet/chardet requests/packages/ && \
	    rm -fr chardet

idna:
	git clone https://github.com/kjd/idna.git && \
	    rm -fr requests/packages/idna && \
	    cd idna && \
	    git checkout `git describe --abbrev=0 --tags` && \
	    cd .. && \
	    mv idna/idna requests/packages/ && \
	    rm -fr idna

publish:
	pip install 'twine>=1.5.0'
	python setup.py sdist
	python setup.py bdist_wheel --universal
	twine upload dist/*
	rm -fr build dist .egg requests.egg-info

docs:
	cd docs && make html
	@echo "\033[95m\n\nBuild successful! View the docs homepage at docs/_build/html/index.html.\n\033[0m"
