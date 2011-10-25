#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>

void handler(int i) {
        write(1, "Hello\n", 6);
}

int main(void) {
        struct sigaction s = {.sa_handler = handler};

        if (sigaction(SIGTRAP, &s, NULL) != 0) {
                abort();
        }

        if (prctl(PR_SET_SECCOMP, 1, 0, 0) == -1) {
                abort();
        }
}
