.PHONY: docs
init:
	python -m pip install -r requirements-dev.txt
test:
	# This runs all of the tests on all supported Python versions.
	tox -p
ci:
	python -m coverage run -m pytest --junitxml=report.xml

test-readme:
	python -m pip install twine build
	python -m build
	python -m twine check dist/*

flake8:
	python -m flake8 src/requests

coverage:
	python -m coverage run -m pytest

publish:
	python -m pip install 'twine>=1.5.0' build
	python -m build
	twine upload dist/*

docs:
	cd docs && make html
	@echo "\033[95m\n\nBuild successful! View the docs homepage at docs/_build/html/index.html.\n\033[0m"
