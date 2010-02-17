#include <unistd.h>

#include "common.h"

size_t xread(int fd, void *buf, size_t count) {
        ssize_t ret = read(fd, buf, count);

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

}
