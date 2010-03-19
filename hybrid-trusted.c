#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>           /* For O_* constants */
#include <error.h>
#include <unistd.h>
#include <asm/unistd.h>

#define SHMEM_NAME "/seccompnurse"
#define SHMEM_MODE 0700
#define SHMEM_SIZE 0x10

#define CONTROL_FD 3
#define OFFSET_SYSCALL_DROPBOX 0
#define PING "PING"

#define TEST_FILE "/tmp/seccomp-nurse.test"

struct registers {
        unsigned int eax, ebx, ecx, edx, esi, edi;
};

void relay_orders(char *protected_area, char *remote_addr) {
        struct registers *regs = (struct registers *)protected_area;
        unsigned int offset = sizeof(*regs);
        char *buf1 = protected_area+offset;

        memcpy(buf1, TEST_FILE, sizeof TEST_FILE);
        memset(regs, 0, sizeof regs);

        *(buf1) = '.';
        while (1) {
                regs->eax = __NR_write;
                regs->ebx = STDOUT_FILENO;
                regs->ecx = remote_addr+offset;
                regs->edx = 1;
                write(CONTROL_FD, PING, sizeof PING);
                sleep(1);
        }
}

int main(int argc, char *argv[]) {
        int fd;
        unsigned int remoteoffset;
        void *shmem;
        char *remote_protected_area;
        int *flag;

        fd = shm_open(SHMEM_NAME, O_CREAT|O_RDWR, SHMEM_MODE);
        if (fd < 0) {
                perror("shm_open()");
                exit(1);
        }

        if (ftruncate(fd, SHMEM_SIZE) != 0) {
                perror("ftruncate()");
                goto unlink_shmem;
        }

        shmem = mmap(NULL, SHMEM_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
        if (shmem == MAP_FAILED) {
                perror("mmap()");
                goto unlink_shmem;
        }

        read(3, &remote_protected_area, sizeof remote_protected_area);
        remoteoffset = abs(remote_protected_area - (int)shmem);
        relay_orders(shmem, remote_protected_area);

unlink_shmem:
        if (shm_unlink(SHMEM_NAME) != 0) {
                perror("shm_unlink()");
                exit(2);
        }

 unmap_shmem:
        if (munmap(shmem, SHMEM_SIZE) != 0) {
                perror("munmap()");
                exit(4);
        }
}
