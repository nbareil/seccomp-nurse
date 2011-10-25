#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void)
{
        int fd = open("/dev/null", O_RDWR);

        if (fd < 0)
                _exit(1);

        read(STDIN_FILENO, NULL, 4);

        _exit(0);
}
