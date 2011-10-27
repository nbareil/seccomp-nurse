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

volatile unsigned int is_son_ready_to_hook_vdso = 0;
void * sync_companion(void *t) {
        /*
         * from now on, the libc has done every function calls needed, we can safely
         * let the child hook the VDSO 
         */
        is_son_ready_to_hook_vdso=1;
        companion_routine();

}
