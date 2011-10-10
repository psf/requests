init:
	pip install -r reqs.txt

test:
	nosetests tests/integration_tests.py --processes=25

ci: init
	nosetests --processes=25  --source-folder=. --with-nosexunit tests/*.py
	pyflakes requests | awk -F\: '{printf "%s:%s: [E]%s\n", $1, $2, $3}' > violations.pyflakes.txt

site:
	cd docs; make dirhtml

docs: site
