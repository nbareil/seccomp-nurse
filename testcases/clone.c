#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sched.h>

int hello(void *v) {
        //write(1, "Hello world!\n", 13);
        printf("Hello world\n");
        return 0;
}

int main(void) {
        char * stack = malloc(4096);
        clone(hello, stack+2048, CLONE_FILES|CLONE_VM, 12);
        printf("Dady is home....\n");
        //write(1, "Daddy is home...\n", 17);
}
