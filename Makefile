#! /usr/bin/make -f

CFLAGS=-Wall -w -Wextra -g -fpie
BINARIES=sandbox.so

%.o: %.s
	cpp $< -o $<.s
	$(CC) $(CFLAGS) -c $<.s -o $@
	rm $<.s

.PHONY: all clean

all: $(BINARIES) sizeof.py

sandbox.so: companion.o common.o helper.o jail.o inject.o preload.o
	gcc -shared -WI,soname,$@.1 -o $@ $^ -lc -ldl -lrt

clean:
	rm -f *.so *.o *pyc $(BINARIES)

check: companion.o
	@echo "Checking there is no stack usage..."
	@objdump -D $< |(grep -E '\<(esp|ebp|call|ret|push|pop)\>' && exit 1; exit 0)

cloner: syscalls.o jail.c inject.c helper.c common.c companion.s cloner.c

sizeof.py: testcases/sizeof
	$< > $@
