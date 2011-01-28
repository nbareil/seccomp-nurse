#include <unistd.h>
#include <sys/syscall.h>

#include "common.h"

int xclone(int (*fn)(void *), void *child_stack,
          int flags, void *arg)
{
        int ret;

        asm("int $0x80"
            : "=a" (ret)
            : "a" (SYS_clone),
              "b" (fn),
              "c" (child_stack),
              "d" (flags),
            "S" (arg));
        return ret;
}


size_t xwrite(int fd, void *buf, size_t count) {
        ssize_t ret;

        asm("int $0x80"
            : "=a" (ret)
            : "a" (SYS_write)
              , "b" (fd)
              , "c" (buf)
              , "d" (count)
            : "memory");

        if (ret < 0) {
                PERROR("read failed");
        }

        return ret;
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
