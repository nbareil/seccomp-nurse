#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#include "common.h"

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
