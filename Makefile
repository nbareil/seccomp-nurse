#! /usr/bin/make -f

CFLAGS=-O2 -Wall -w -Wextra

libgs.so.1.0.1: dlmalloc.o mm.o helper.o jail.o inject.o
	gcc -shared -WI,soname,libgs.so.1 -o libgs.so.1.0.1 dlmalloc.o mm.o helper.o jail.o inject.o -lc -ldl

dlmalloc.o:
	$(CC) $(CFLAGS) -DMSPACES=1 -DUSE_DL_PREFIX=1 -DONLY_MSPACES=1 -c $(@:.o=.c)

.PHONY: syscalls clean

syscalls: gen_syscall_lists.py syscall.py
	rm -fr autogen
	mkdir autogen
	python gen_syscall_lists.py > autogen/syscall_32.py

clean:
	rm -f *.o *pyc
	rm -f libgs.so.1.0.1
	rm -fr autogen
