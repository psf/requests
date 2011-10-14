init:
	pip install -r reqs.txt

test:
	nosetests test_requests.py --processes=30

ci: init
	nosetests --search-test --processes=30 --with-nosexunit test_requests.py
	pyflakes requests | awk -F\: '{printf "%s:%s: [E]%s\n", $1, $2, $3}' > violations.pyflakes.txt

site:
	cd docs; make dirhtml

docs: site
