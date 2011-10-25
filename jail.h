#ifndef __JAIL_H
#define __JAIL_H

int (*real_handler)(void);
void handler_in_seccomp(void);
void handler_int80(void);

#endif
