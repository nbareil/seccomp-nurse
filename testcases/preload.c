#include <asm/unistd_32.h>


void *dlopen(const char *filename, int flag)
{
        printf("dlopen()********************************************************************************\n");
}

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
        int ret;

        printf("gettimeofday() ************************************************************************\n");
        asm("call *%%gs:0x10"
            : "=a" (ret)
            : "a" (__NR_gettimeofday)
              , "b" (tv)
              , "c" (tz));

        return ret;
}
