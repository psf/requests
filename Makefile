init:
	pip install -r reqs.txt

test:
	nosetests tests/integration_tests.py --processes=25

site:
	cd docs; make dirhtml

docs: site
