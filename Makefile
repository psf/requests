init:
	pip install -r requirements.txt

test:
	py.test

ci: init
	py.test --junitxml=junit.xml

certs:
	curl http://ci.kennethreitz.org/job/ca-bundle/lastSuccessfulBuild/artifact/cacerts.pem -o requests/cacert.pem

deps: urllib3 charade

urllib3:
	rm -fr requests/packages/urllib3
	git clone https://github.com/shazow/urllib3.git
	mv urllib3/urllib3 requests/packages/
	rm -fr urllib3

charade:
	rm -fr requests/packages/charade
	git clone https://github.com/sigmavirus24/charade.git
	mv charade/charade requests/packages/
	rm -fr charade
