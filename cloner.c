#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/prctl.h>

#include "common.h"

char dummy_stack[4096];
char junk[4];
extern void handler_in_seccomp(void);


struct sharepoint {
        char space[512];          /* mm0 */
        char syscall_dropbox[28]; /* mm1 */
        char retarray[256];       /* mm2 */
        sigset_t sigset;
} __attribute__ ((packed));


int trustee(void *v)
{
        int fd;
        struct sharepoint *sharedmemory;
        void *ptr;

        /* do */
        {
                fd = xopen("/dev/shm/seccomp-nurse", O_RDONLY|O_CREAT, 277);
        }
        /* while (fd < 0); */

        sharedmemory = (struct sharepoint *)xmmap(NULL, sizeof sharedmemory, PROT_READ, MAP_SHARED, fd, 0);
        xwrite(1, "Hello world\n", 12);

        ptr = sharedmemory;
        xwrite(3, &ptr, 4);

        asm("pxor %mm0, %mm0\n"
            "pxor %mm1, %mm1\n"
            "pxor %mm2, %mm2\n");

        ptr = (void *)sharedmemory->space;
        asm("movd %0, %%mm0\n" : : "m" (ptr));

        ptr = (void *)sharedmemory->syscall_dropbox;
        asm("movd %0, %%mm1\n" : : "m" (ptr));

        ptr = (void *)sharedmemory->retarray;
        asm("movd %0, %%mm2\n" : : "m" (ptr));

	if (xprctl(PR_SET_SECCOMP, 1, 0, 0, 0) == -1)
                xexit(4);

        /* hijack VDSO now */
        asm("mov %0, %%ebx\n"
            "mov %%ebx, %%gs:0x10\n"
            :
            : "r" (handler_in_seccomp)
            : "ebx");
        _exit(12);
}


int main(void)
{

        int ret;

        xwrite(1, "tata\n", 5);
        ret = xclone(trustee, dummy_stack+sizeof dummy_stack, CLONE_FILES |CLONE_VM, NULL);
        xwrite(1, "toto\n", 5);
        xexit(3);
}
