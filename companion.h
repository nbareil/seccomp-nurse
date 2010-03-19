
#ifndef __COMPANION_H
#define __COMPANION_H

#define JUNK_SIZE 4
#define OFFSET_SYSCALL_DROPBOX 0

unsigned int range_start, range_end, syscall_dropbox;
char junk_zone[JUNK_SIZE];
char retarray[256];

extern void companion_routine(void);

#endif
