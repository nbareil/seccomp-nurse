#! /usr/bin/make -f

CFLAGS=-O2 -Wall -w -Wextra -g
BINARIES=sandbox.so sandbox

.PHONY: all clean

all: $(BINARIES)

sandbox.so: companion.o common.o helper.o jail.o inject.o
	gcc -shared -WI,soname,$@.1 -o $@ $^ -lc -ldl -lrt

clean:
	rm -f *.so *.o *pyc $(BINARIES)


