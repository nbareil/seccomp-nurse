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

#include <linux/unistd.h>

static void hijack_vdso_gate(void) {
	asm("mov %%gs:0x10, %%ebx\n"
	    "mov %%ebx, %0\n"

	    "mov %1, %%ebx\n"
	    "mov %%ebx, %%gs:0x10\n"

	    : "=m" (real_handler)
	    : "r" (handler_in_seccomp)
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

volatile unsigned int is_son_ready_to_hook_vdso = 0;
void * sync_companion(void *t) {
        /*
         * from now on, the libc has done every function calls needed, we can safely
         * let the child hook the VDSO 
         */
        is_son_ready_to_hook_vdso=1;
        companion_routine();

}
