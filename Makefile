#! /usr/bin/make -f

CFLAGS=-O2 -Wall -w -Wextra -g
BINARIES=sandbox.so

.PHONY: all clean

all: $(BINARIES) sizeof.py

sandbox.so: companion.o common.o helper.o jail.o inject.o
	gcc -shared -WI,soname,$@.1 -o $@ $^ -lc -ldl -lrt

clean:
	rm -f *.so *.o *pyc $(BINARIES)

check: companion.o
	@echo "Checking there is no stack usage..."
	@objdump -D $< |(grep -E '\<(esp|ebp|call|ret|push|pop)\>' && exit 1; exit 0)

sizeof.py: t/sizeof
	$< > $@
