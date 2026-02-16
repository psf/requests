.PHONY: all clean ca server

ca:
	make -C $@ all

server:
	make -C $@ all

all: ca server

clean:
	make -C ca clean
	make -C server clean
