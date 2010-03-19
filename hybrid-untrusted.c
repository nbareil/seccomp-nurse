#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>           /* For O_* constants */
#include <error.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sched.h>

#include <dlfcn.h>
#include <link.h>

#include "common.h"
#include "inject.h"
#include "jail.h"
#include "mm.h"

#define SHMEM_NAME "/seccompnurse"
#define SHMEM_MODE 277
#define SHMEM_SIZE 0x10
#define JUNK_SIZE 4
#define OFFSET_SYSCALL_DROPBOX 0

extern void helper_start(void);
unsigned int range_start, range_end, syscall_dropbox;
char junk_zone[JUNK_SIZE];

int trusted_thread(void *shmem) {
        helper();
        exit(0);
}


