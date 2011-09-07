init:
	pip install -r reqs.txt

test:
	python test_requests.py

site:
	cd docs; make dirhtml

docs: site
