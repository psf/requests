.PHONY: docs

init:
	pip install -r requirements.txt
test:
	# This runs all of the tests. To run an individual test, run py.test with
	# the -k flag, like "py.test -k test_path_is_not_double_encoded"
	py.test --boxed -n 9 tests/

test-readme:
	python setup.py check -r -s

coverage:
	py.test --cov-config .coveragerc --verbose --cov-report term --boxed -n 9 --cov-report xml --cov=requests tests

publish:
	pip install 'twine>=1.5.0'
	python setup.py sdist bdist_wheel
	twine upload dist/*
	rm -fr build dist .egg requests.egg-info

docs:
	cd docs && make html
	@echo "\033[95m\n\nBuild successful! View the docs homepage at docs/_build/html/index.html.\n\033[0m"
