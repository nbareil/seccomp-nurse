#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <malloc.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int main(int argc, char *argv[]) {
        char buf[512];
        FILE *f = fopen("/etc/passwd", "r");

        if (!f)
                exit(1);

        
        printf("==========> file opened!\n");
        while (fgets(buf, sizeof buf, f) != NULL) {
                printf("> %s", buf);
        }
        fclose(f);

        exit(0);
}
