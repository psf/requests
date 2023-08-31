.PHONY: docs
init:
	python -m pip install -r requirements-dev.txt
test:
	# This runs all of the tests on all supported Python versions.
	tox -p
ci:
	python -m pytest tests --junitxml=report.xml

test-readme:
	python setup.py check --restructuredtext --strict && ([ $$? -eq 0 ] && echo "README.rst and HISTORY.rst ok") || echo "Invalid markup in README.rst or HISTORY.rst!"

flake8:
	python -m flake8 src/requests

coverage:
	python -m pytest --cov-config .coveragerc --verbose --cov-report term --cov-report xml --cov=src/requests tests

publish:
	python -m pip install 'twine>=1.5.0'
	python setup.py sdist bdist_wheel
	twine upload dist/*
	rm -fr build dist .egg requests.egg-info

docs:
	cd docs && make html
	@echo "\033[95m\n\nBuild successful! View the docs homepage at docs/_build/html/index.html.\n\033[0m"
