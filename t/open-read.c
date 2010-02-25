#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void) {
        char buf[100];
        int fd = open("/etc/motd", 0);
        ssize_t ret;

        while ((ret = read(fd, &buf, sizeof buf)) > 0) {
            buf[ret-1] = '\x00';
            write(1, buf, ret);
        }

        close(fd);
}

