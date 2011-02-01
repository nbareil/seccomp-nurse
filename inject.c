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

char junk[JUNK_SIZE];

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

unsigned int la_version(unsigned int version) {
        return version;
}

void la_preinit(uintptr_t *cookie) {
        char dummy_stack[512];
        struct sharepoint *sharedmemory;
        int ret, fd;
        void *ptr;

        do {
                fd = shm_open(SHMEM_NAME, O_RDONLY, SHMEM_MODE);
                if ((fd < 0) && errno != ENOENT) {
                        perror("shm_open()");
                        exit(1);
                }
                sleep(0.5);
        } while (fd < 0);

        sharedmemory = (struct sharepoint *)mmap(NULL, sizeof sharedmemory, PROT_READ, MAP_SHARED, fd, 0);
        if (sharedmemory == MAP_FAILED) {
                perror("mmap()");
                exit(1);
        }
        ptr = sharedmemory;
        xwrite(3, &ptr, 4);

        asm("pxor %mm0, %mm0\n"
            "pxor %mm1, %mm1\n"
            "pxor %mm2, %mm2\n"
            "pxor %mm3, %mm3\n");

        ptr = (void *)sharedmemory->space;
        asm("movd %0, %%mm0\n" : : "m" (ptr));

        ptr = (void *)sharedmemory->syscall_dropbox;
        asm("movd %0, %%mm1\n" : : "m" (ptr));

        ptr = (void *)junk;
        asm("movd %0, %%mm2\n" : : "m" (ptr));

        ptr = (void *)sharedmemory->retarray;
        asm("movd %0, %%mm3\n" : : "m" (ptr));

        ret = clone(companion_routine, dummy_stack+sizeof dummy_stack, CLONE_FILES |CLONE_VM, 12);
        if (ret == -1) {
                perror("clone(trusted)");
                exit(1);
        }

        enter_seccomp_mode();
        hijack_vdso_gate();
}
