#ifndef __COMMON_H
#define __COMMON_H

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sched.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <asm/ptrace.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <signal.h>

#define xstr(x) "$"#x
#define ivalue(x) xstr(x)

#define AUDIT(x, args...) do { fprintf(stderr, "AUDIT: " x, ##args); } while (0)
#define DEBUGP(x, args...) do { fprintf(stdout, "DEBUGP: " x, ##args);} while (0)
#define WARNING(x, args...) do { fprintf(stderr, "WARNING: " x, ##args); } while (0)
#define PERROR(x) do { perror(x); _exit(1); } while (0)
#define ERROR(x, args...) do { fprintf(stderr,"ERROR: " x, ## args); _exit(1); } while (0)

size_t fxread(int fd, void *buf, size_t count);
int xsigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
static inline int __attribute__((always_inline)) xopen(const char *pathname, int flags, int mode)
{
        int ret;
        asm("int $0x80"
            : "=a" (ret)
            : "a" (SYS_open),
              "b" (pathname),
              "c" (flags),
              "d" (mode)
            : "cc");
        return ret;
}

static inline int __attribute__((always_inline)) xprctl(int option, unsigned long arg2, unsigned long arg3,
                 unsigned long arg4, unsigned long arg5)

{
        asm("int $0x80"
            : /* output */
            : "a" (SYS_prctl),
              "b" (option),
              "c" (arg2),
              "d" (arg3),
              "S" (arg4),
              "D" (arg5));
}


static inline void __attribute__((always_inline)) xexit(int status)
{
        asm("int $0x80"
            : /* output */
            : "a" (SYS_exit),
              "b" (status));
}

static inline size_t __attribute__((always_inline)) xwrite(int fd, void *buf, size_t count) {
        asm("int $0x80"
            :
            : "a" (SYS_write)
              , "b" (fd)
              , "c" (buf)
              , "d" (count)
            : "memory");

}


static inline int __attribute__((always_inline)) xclone(int (*fn)(void *), void *child_stack,
           int flags, void *arg)
{
        int ret;
        child_stack -= 4;
        *((unsigned int *)child_stack) = (unsigned int)fn;

        asm("int $0x80\n"
            "test %%eax, %%eax\n"
            "jnz 1f\n"
            "pop %%ebx\n"
            "jmp *%%ebx\n"
            "1: nop\n"

            : "=a" (ret)
            : "a" (SYS_clone),
              "b" (flags),
              "c" (child_stack),
              "d" (0),
              "S" (0),
              "D" (0));
        return ret;
}

#endif
