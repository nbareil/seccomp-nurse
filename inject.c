#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <stdlib.h>

#include "common.h"
#include "inject.h"
#include "jail.h"
#include "mm.h"

int wrap_main(int argc, char **argv, char **environ)
{
	pid_t pid;
	char *dir = strdup("/tmp/libnail-XXXXXX");
	

	dir=mkdtemp(dir);
	if (!dir)
		PERROR("mkdtemp() failed");

	pid = fork();
	if (pid > 0) {
		start_trusted_process(dir, pid);

	} else if (pid == 0) {
		jail_exec(dir, argc, argv, environ);

	} else {
		PERROR("fork()");
	}

	return 0;
}

int __libc_start_main(main_t main,
		      int argc,
		      char *__unbounded *__unbounded ubp_av,
		      ElfW(auxv_t) *__unbounded auxvec,
		      __typeof (main) init,
		      void (*fini) (void),
		      void (*rtld_fini) (void), void *__unbounded stack_end)
{
	void *libc;
	int (*libc_start_main)(main_t main, 
			       int,
			       char *__unbounded *__unbounded,
			       ElfW(auxv_t) *,
			       __typeof (main), 
			       void (*fini) (void),
			       void (*rtld_fini) (void),
			       void *__unbounded stack_end);

	DEBUGP(" [+] Loading libc...\n");
	libc = dlopen("libc.so.6", RTLD_LOCAL  | RTLD_LAZY);
	if (!libc)
		ERROR("	 dlopen() failed: %s\n", dlerror());

	DEBUGP(" [+] Calling __libc_start_main of %s...\n", ubp_av[0]);
	libc_start_main = dlsym(libc, "__libc_start_main");
	if (!libc_start_main)
		ERROR("	    Failed: %s\n", dlerror());

	realmain = main;
	void (*__malloc_initialize_hook) (void) = my_malloc_init;
	return (*libc_start_main)(wrap_main, argc, ubp_av, auxvec, init, fini, rtld_fini, stack_end);
}

