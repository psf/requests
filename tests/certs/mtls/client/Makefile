.PHONY: all clean

client.key:
	openssl genrsa -out $@ 2048

client.csr: client.key
	openssl req -key $< -new -out $@ -config cert.cnf

client.pem: client.csr
	openssl x509 -req -CA ./ca/ca.crt -CAkey ./ca/ca-private.key -in client.csr -outform PEM -out client.pem -days 730 -CAcreateserial
	openssl x509 -in ./ca/ca.crt -outform PEM >> $@

all: client.pem

clean:
	rm -f client.*
