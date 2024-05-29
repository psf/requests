.PHONY: docs

init:
	pip install -r requirements.txt

test:
	# This runs all of the tests. To run an individual test, run py.test with
	# the -k flag, like "py.test -k test_path_is_not_double_encoded"
	py.test tests

coverage:
	py.test --verbose --cov-report term --cov=requests tests

ci: init
	py.test --junitxml=junit.xml

certs:
	curl http://ci.kennethreitz.org/job/ca-bundle/lastSuccessfulBuild/artifact/cacerts.pem -o requests/cacert.pem

deps: urllib3 chardet idna

urllib3:
	git clone https://github.com/shazow/urllib3.git && \
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
	    find requests/packages/idna -type f -exec sed -i "" "s/^from idna/from /" {} \; && \
	    rm -fr idna

publish:
	python setup.py register
	python setup.py sdist upload
	python setup.py bdist_wheel --universal upload
	rm -fr build dist .egg requests.egg-info


docs-init:
	pip install -r docs/requirements.txt

docs:
	cd docs && make html
	@echo "\033[95m\n\nBuild successful! View the docs homepage at docs/_build/html/index.html.\n\033[0m"
