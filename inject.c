#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#define _GNU_SOURCE
#include <sched.h>
#include <sys/prctl.h>

#include "common.h"
#include "inject.h"
#include "jail.h"
#include "companion.h"
#include "mm.h"

static void hijack_vdso_gate(void) {
	asm("mov %%gs:0x10, %%ebx\n"
	    "mov %%ebx, %0\n"

	    "mov %1, %%ebx\n"
	    "mov %%ebx, %%gs:0x10\n"

	    : "=m" (real_handler)
	    : "r" (handler)
	    : "ebx");
} __attribute__((always_inline));

void enter_seccomp_mode(void) {
	if (prctl(PR_SET_SECCOMP, 1, 0, 0) == -1) {
		perror("prctl(PR_SET_SECCOMP) failed");
		printf("Maybe you don't have the CONFIG_SECCOMP support built into your kernel?\n");
		exit(1);
	}
}

void fill_return_table(char *array) {
	int i = 0;
	while (i < 256)
		*(array+i) = (char)i++;
        /* XXX: need to mptrotect() this zone */
}

unsigned int la_version(unsigned int version) {
        return version;
}

void la_preinit(uintptr_t *cookie) {
        char dummy_stack[512];
        void *sharedmemory;
        int ret, fd;
        do {
                fd = shm_open(SHMEM_NAME, O_RDONLY, SHMEM_MODE);
                if ((fd < 0) && errno != ENOENT) {
                        perror("shm_open()");
                        exit(1);
                }
                sleep(0.5);
        } while (fd < 0);

        sharedmemory = mmap(NULL, SHMEM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
        if (sharedmemory == MAP_FAILED) {
                perror("mmap()");
                exit(1);
        }

        range_start = sharedmemory;
        range_end   = sharedmemory+SHMEM_SIZE;
        syscall_dropbox = sharedmemory+OFFSET_SYSCALL_DROPBOX;

        fill_return_table(retarray);

        write(3, &range_start, sizeof range_start);
        write(3, &range_end, sizeof range_end);
        ret = clone(companion_routine, dummy_stack+sizeof dummy_stack, CLONE_FILES|CLONE_VM, 12);
        if (ret == -1) {
                perror("clone(trusted)");
                exit(1);
        }

        enter_seccomp_mode();
        hijack_vdso_gate();
}
