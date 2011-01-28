#ifndef __COMMON_H
#define __COMMON_H

#include <stdio.h>

#define xstr(x) "$"#x
#define ivalue(x) xstr(x)

#define AUDIT(x, args...) do { fprintf(stderr, "AUDIT: " x, ##args); } while (0)
#define DEBUGP(x, args...) do { fprintf(stdout, "DEBUGP: " x, ##args);} while (0)
#define WARNING(x, args...) do { fprintf(stderr, "WARNING: " x, ##args); } while (0)
#define PERROR(x) do { perror(x); _exit(1); } while (0)
#define ERROR(x, args...) do { fprintf(stderr,"ERROR: " x, ## args); _exit(1); } while (0)


int xclone(int (*fn)(void *), void *child_stack, int flags, void *arg);
size_t xread(int fd, void *buf, size_t count);
size_t xwrite(int fd, void *buf, size_t count);
size_t fxread(int fd, void *buf, size_t count);

#endif
