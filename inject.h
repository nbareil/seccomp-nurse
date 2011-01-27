#ifndef __INJECT_H
#define __INJECT_H
#include <signal.h>

#define ElfW(type)	_ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)	e##w##t
#define __ELF_NATIVE_CLASS __WORDSIZE

#define SHMEM_NAME "/seccompnurse"
#define SHMEM_MODE 277
#define SHMEM_SIZE 0x10


struct sharepoint {
        char space[512];          /* mm0 */
        char syscall_dropbox[28]; /* mm1 */
        char *junk;               /* mm2 */
        char retarray[256];       /* mm3 */
        sigset_t sigset;
} __attribute__ ((packed));

typedef int (*main_t)(int, char **, char **);
main_t realmain;
#endif
