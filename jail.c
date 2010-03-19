#include <stdio.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "jail.h"
#include "helper.h"
#include "inject.h"

void syscall_proxy(void) {
	char buf[8*4];
	unsigned int nrsyscall;
	int ret = 0;
	int wrote;

	asm ("pushl %eax\n");
	asm ("movl $1, (%%eax)\n"
	     "popl         4(%%eax)\n"
	     "movl %%ebx,  8(%%eax)\n"
	     "movl %%ecx, 12(%%eax)\n"
	     "movl %%edx, 16(%%eax)\n"
	     "movl %%esi, 20(%%eax)\n"
	     "movl %%edi, 24(%%eax)\n"
             "movl (%%ebp), %%ebx\n" // gcc prologue pushed ebp, and I want its initial value
	     "movl %%ebx, 28(%%eax)\n"
	     :: "a" (buf) );

	write(CONTROL_FD, buf, sizeof buf);
	ret = wait_for_orders(CONTROL_FD);
        asm("movl %0, %%eax\n" : : "m" (ret));
}

void (*syscall_proxy_addr)(void) = syscall_proxy;
void handler(void) {
	asm("movl (%%ebp), %%ebp\n" // ignore the gcc prologue
            "cmpl " ivalue(__NR_write) ", %%eax\n"
            //	    "je wrap_read\n"
            "je do_syscall\n"

	    "cmpl " ivalue(__NR_read) ", %%eax\n"
            //	    "je wrap_read\n"
            "je do_syscall\n"

	    "cmpl " ivalue(__NR_exit_group) ", %%eax\n"
	    "jne wrapper\n"
	    "movl " ivalue(__NR_exit) ", %%eax\n"
	    "jmp do_syscall\n"

	    "wrapper:\n"
	    "			pushl %%ebx\n"
	    "			pushl %%ecx\n"
	    "			pushl %%edx\n"
	    "			pushl %%esi\n"
	    "			pushl %%edi\n"
	    "			call *%0\n"
	    "			popl %%edi\n"
	    "			popl %%esi\n"
	    "			popl %%edx\n"
	    "			popl %%ecx\n"
	    "			popl %%ebx\n"
	    "			jmp out\n"

	    "do_syscall:\n"
	    "			call *%1\n"
	    "			jmp out\n"

	    "wrap_write:\n"
	    "			cmp " ivalue(__NR_write) ", %%ebx\n"
	    "			jle do_syscall\n"
	    "			jmp wrapper\n"

	    "wrap_read:\n"
            "			cmpl $4, %%ebx\n"   /* master socket? */
            "			je do_syscall\n"
            "			jmp wrapper\n"
	    "			\n"

	    "out:		nop\n"
	    : /* output */
	    : "m" (syscall_proxy_addr),
	      "m" (real_handler));
}
