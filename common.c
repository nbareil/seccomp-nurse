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

int xsigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
        asm("movl " ivalue(__NR_sigaction) ", %%eax\n"
            "movl %0, %%ebx\n"
            "movl %1, %%ecx\n"
            "int $0x80\n"
            : /* output */
            : /* input */
              "m" (signum), "m" (act), "m" (oldact));
}

size_t xread(int fd, void *buf, size_t count) {
        ssize_t ret;

        asm("int $0x80"
            : "=a" (ret)
            : "a" (SYS_read)
              , "b" (fd)
              , "c" (buf)
              , "d" (count)
            : "memory");

        if (ret < 0) {
                PERROR("read failed");
        }

        return ret;
}

size_t fxread(int fd, void *buf, size_t count) {
        size_t ret;

        ret = xread(fd, buf, count);
        if (ret != count) {
                ERROR("read too short ret=%d count=%d", ret, count);
        }
        return ret;
}

void * xmmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
        asm("push %%ebx\n"
            "push %%ecx\n"
            "push %%edx\n"
            "push %%esi\n"
            "push %%edi\n"
            "push %%ebp\n"
            "mov %0, %%eax\n"
            "mov %1, %%ebx\n"
            "mov %2, %%ecx\n"
            "mov %3, %%edx\n"
            "mov %4, %%esi\n"
            "mov %5, %%edi\n"
            "mov %6, %%ebp\n"
            "int $0x80\n"
            "pop %%ebp\n"
            "pop %%edi\n"
            "pop %%esi\n"
            "pop %%edx\n"
            "pop %%ecx\n"
            "pop %%ebx\n"
            :
            : "r" (SYS_mmap2),
              "m" (addr),
              "m" (length),
              "m" (prot),
              "m" (flags),
              "m" (fd),
              "m" (offset));
}
