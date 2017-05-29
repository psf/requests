.PHONY: docs
init:
	pip install -r requirements.txt
test:
	# This runs all of the tests, on both Python 2 and Python 3.
	detox
ci:
	python setup.py test

test-readme:
	python setup.py check -r -s

flake8:
	flake8 --ignore=E501 requests

coverage:
	py.test --cov-config .coveragerc --verbose --cov-report term --cov-report xml --cov=requests tests

publish:
	pip install 'twine>=1.5.0'
	python setup.py sdist bdist_wheel
	twine upload dist/*
	rm -fr build dist .egg requests.egg-info

docs:
	cd docs && make html
	@echo "\033[95m\n\nBuild successful! View the docs homepage at docs/_build/html/index.html.\n\033[0m"