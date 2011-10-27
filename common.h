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
#define ERROR(x, args...) do { fprintf(stderr,"ERROR: " x, ## args); xexit(1); } while (0)

size_t  fxread(int fd, void *buf, size_t count);

static inline void __attribute__((always_inline)) xexit(int status)
{
        xsyscall3(SYS_exit, status, 0, 0);
}

static inline ssize_t __attribute__((always_inline)) xread(int fd, void *buf, size_t count)
{
        ssize_t ret = xsyscall3(SYS_read, fd, buf, count);

        if (ret < 0) {
                xexit(1);
        }

        return ret;
}

static inline ssize_t __attribute__((always_inline)) xwrite(int fd, void *buf, size_t count)
{
        ssize_t ret = xsyscall3(SYS_write, fd, buf, count);

        if (ret < 0) {
                xexit(1);
        }

        return ret;
}

static inline int __attribute__((always_inline)) xsigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
        return xsyscall3(SYS_sigaction, signum, act, oldact);
}

static inline int __attribute__((always_inline)) xopen(const char *pathname, int flags, int mode)
{
        return xsyscall3(SYS_open, pathname, flags, mode);
}

static inline int __attribute__((always_inline)) xenableseccomp(void)
{
        return xsyscall3(SYS_prctl, PR_SET_SECCOMP, 1, 0);
}



#endif
