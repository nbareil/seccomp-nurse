#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

/* This matches struct stat64 in glibc2.1. Only used for 32 bit. */
struct stat64 {
    unsigned long long st_dev;  /* Device.  */
    unsigned long long st_ino;  /* File serial number.  */
    unsigned int    st_mode;    /* File mode.  */
    unsigned int    st_nlink;   /* Link count.  */
    unsigned int    st_uid;     /* User ID of the file's owner.  */
    unsigned int    st_gid;     /* Group ID of the file's group. */
    unsigned long long st_rdev; /* Device number, if device.  */
    unsigned long long __pad1;
    long long   st_size;    /* Size of file, in bytes.  */
    int     st_blksize; /* Optimal block size for I/O.  */

    int     __pad2;
    long long   st_blocks;
    int     st_atime;
    unsigned int    st_atime_nsec;
    int     st_mtime;
    unsigned int    st_mtime_nsec;
    int     st_ctime;
    unsigned int    st_ctime_nsec;
    unsigned int    __unused4;
    unsigned int    __unused5;
};


void hexdump(void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}

int main(void) {
    int fd = open("/etc/motd", 0);
    struct stat64 st;

/*    struct stat st;

    fstat(fd, &st);*/
    hexdump(&st, sizeof st);
    close(fd);
}
