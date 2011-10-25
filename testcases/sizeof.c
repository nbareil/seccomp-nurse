#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    printf("sockaddr     = %3d\n", sizeof(struct sockaddr));
    printf("stat         = %3d\n", sizeof(struct stat));

struct manpage_linux_dirent {
    unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[];  /* Filename (null-terminated) */
                        /* length is actually (d_reclen - 2 -
                           offsetof(struct linux_dirent, d_name) */
    /*
    char           pad;       // Zero padding byte
    char           d_type;    // File type (only since Linux 2.6.4;
                              // offset is (d_reclen - 1))
    */

};
    printf("linux_dirent = %3d\n", sizeof(struct manpage_linux_dirent));

#include <event.h>
    printf("event        = %3d\n", sizeof(struct event));

#include <sys/uio.h>
    printf("iovec        = %3d\n", sizeof(struct iovec));

#include <time.h>
    printf("time_t       = %3d\n", sizeof(time_t));

#include <sys/times.h>
    printf("tms          = %3d\n", sizeof(struct tms));
    return 0;
}

