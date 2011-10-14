init:
	pip install -r reqs.txt

test:
	nosetests test_requests.py --processes=30

ci: init
	nosetests --processes=30 --with-nosexunit test_requests.py

site:
	cd docs; make dirhtml

docs: site
