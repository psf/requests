init:
	pip install -r reqs.txt

test:
	python test_requests.py

site:
	# Building Docs

docs: site
	cd docs; make dirhtml