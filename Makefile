init:
	python setup.py develop
	pip install -r requirements.txt

test:
	nosetests  test_requests.py

ci: init
	nosetests test_requests.py --with-xunit --xunit-file=junit-report.xml

stats:
	pyflakes requests | awk -F\: '{printf "%s:%s: [E]%s\n", $1, $2, $3}' > violations.pyflakes.txt

site:
	cd docs; make dirhtml

pyc:
	find . -name "*.pyc" -exec rm '{}' ';'

deps:
	rm -fr requests/packages/urllib3
	git clone https://github.com/shazow/urllib3.git
	cd urllib3 && git checkout python3 && cd ..
	mv urllib3/urllib3 requests/packages/
	rm -fr urllib3

docs: site
