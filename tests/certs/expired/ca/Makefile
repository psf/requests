.PHONY: all clean

root_files = ca-private.key ca.crt

ca-private.key:
	openssl genrsa -out ca-private.key 2048

all: ca-private.key
	openssl req -x509 -sha256 -days 7300 -key ca-private.key -out ca.crt -config ca.cnf
	ln -s ca.crt cacert.pem

clean:
	rm -f cacert.pem ca.crt ca-private.key *.csr
