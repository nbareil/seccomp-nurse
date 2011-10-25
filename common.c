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

