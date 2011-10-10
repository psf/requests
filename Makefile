init:
	pip install -r reqs.txt

test:
	nosetests tests/integration_tests.py --processes=25

ci: init
	nosetests --search-test --processes=30 --with-nosexunit tests/*.py
	pyflakes requests | awk -F\: '{printf "%s:%s: [E]%s\n", $1, $2, $3}' > violations.pyflakes.txt

site:
	cd docs; make dirhtml

docs: site
