#include <dlfcn.h>

int main(void) {
        dlopen("/usr/lib/python2.6/lib-dynload/readline.so", RTLD_LAZY);
}
