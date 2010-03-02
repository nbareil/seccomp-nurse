#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
        ssize_t ret;
        size_t j;
        struct stat st;
        char *addr;
        int fd = open(argc > 1 ? argv[1] : "/etc/motd", 0);

        fstat(fd, &st);
        addr = mmap(0, st.st_size, 0x1, 0x2, fd, 0);

        j=0;
        while (j < st.st_size) {
                j += write(1, addr+j, st.st_size -j);
        }
        close(fd);
}

