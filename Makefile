.PHONY: docs

init:
	pip install -r requirements.txt

test:
	py.test

coverage:
	py.test --verbose --cov-report term --cov=requests test_requests.py

ci: init
	py.test --junitxml=junit.xml

certs:
	curl http://ci.kennethreitz.org/job/ca-bundle/lastSuccessfulBuild/artifact/cacerts.pem -o requests/cacert.pem

deps: urllib3 chardet

urllib3:
	rm -fr requests/packages/urllib3
	git clone https://github.com/shazow/urllib3.git
	mv urllib3/urllib3 requests/packages/
	rm -fr urllib3

chardet:
	rm -fr requests/packages/chardet
	git clone https://github.com/chardet/chardet.git
	mv chardet/chardet requests/packages/
	rm -fr chardet

publish:
	python setup.py register
	python setup.py sdist upload
	python setup.py bdist_wheel upload


docs-init:
	pip install -r docs/requirements.txt

docs:
	cd docs && make html
	@echo "\033[95m\n\nBuild successful! View the docs homepage at docs/_build/html/index.html.\n\033[0m"
