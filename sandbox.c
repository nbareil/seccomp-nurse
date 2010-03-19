#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>           /* For O_* constants */
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/socket.h>

#include "helper.h"

extern char **environ;

#define TRUSTED_PATH "./hybrid.py"

int main(int argc, char *argv[]) {
        int control_sockets[2], thread_sockets[2];
        pid_t untrusted, trusted;
        int ret;

        if (argc <= 1) {
                fprintf(stderr,
                        "Usage: %s <cmd> <arguments>\n"
                        "      sandbox the command specified\n",
                        argv[0]);
                exit(1);
        }

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, control_sockets) != 0) {
                perror("socketpair()");
                exit(1);
        }

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, thread_sockets) != 0) {
                perror("socketpair()");
                exit(1);
        }

        untrusted = fork();
        if (untrusted > 0) {
                dup2(control_sockets[1], THREAD_FD);
                dup2(thread_sockets[1], CONTROL_FD);
                close(6);
                close(5);

                setenv("LD_PRELOAD", "./sandbox.so", 1);
                execve(argv[1], argv+1, environ);
                perror("execve()");
                exit(4);

        } else if (untrusted == 0) {
                trusted = fork();

                if (trusted > 0) {
                        close(thread_sockets[1]);  /* 4 is closed */
                        close(control_sockets[1]); /* 6 is closed */
                        dup2(thread_sockets[0], CONTROL_FD);
                        close(thread_sockets[0]);

                        execve(TRUSTED_PATH, NULL, NULL);
                } else if (trusted == 0) {
                        waitpid(untrusted, &ret, 0);
                        waitpid(trusted, &ret, 0);
                } else {
                        perror("fork()");
                        exit(5);
                }

        } else {
                perror("fork()");
                exit(3);
        }

        return 0;
}
