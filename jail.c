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

	write(controlfd, buf, sizeof buf);
	ret = wait_for_orders(controlfd);
        asm("movl %0, %%eax\n" : : "m" (ret));
}

void (*syscall_proxy_addr)(void) = syscall_proxy;
void handler(void) {
	asm("movl (%%ebp), %%ebp\n" // ignore the gcc prologue
            "cmpl " ivalue(__NR_write) ", %%eax\n"
	    "je wrap_write\n"

	    "cmpl " ivalue(__NR_read) ", %%eax\n"
	    "je wrap_read\n"

	    "cmpl " ivalue(__NR_exit_group) ", %%eax\n"
	    "jne wrapper\n"
	    "movl " ivalue(__NR_exit) ", %%eax\n"
	    "jmp do_syscall\n"

	    "wrapper:\n"
	    "			pushl %%ecx\n"
	    "			call *%0\n"
	    "			popl %%ecx\n"
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

static void hijack_vdso_gate(void) {
	asm("mov %%gs:0x10, %%ebx\n"
	    "mov %%ebx, %0\n"

	    "mov %1, %%ebx\n"
	    "mov %%ebx, %%gs:0x10\n"

	    : "=m" (real_handler)
	    : "r" (handler)
	    : "ebx");
} __attribute__((always_inline));

void enter_seccomp_mode(void) {
	if (prctl(PR_SET_SECCOMP, 1, 0, 0) == -1) {
		perror("prctl(PR_SET_SECCOMP) failed");
		printf("Maybe you don't have the CONFIG_SECCOMP support built into your kernel?\n");
		exit(1);
	}
}

void bind_sockets(const char *dir, int last, unsigned int n) {
	unsigned int i;
	struct sockaddr_un uaddr, client;
	size_t ret;
	socklen_t addrlen = sizeof client;
	int s, prev = last;

	uaddr.sun_family = AF_UNIX;
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (!s)
		PERROR("Cannot allocate another socket");

	ret = snprintf(uaddr.sun_path, sizeof(uaddr.sun_path),
		       "%s/sockets", dir);

	if (ret >= sizeof(uaddr.sun_path))
		ERROR("Unix socket's pathname is truncated.\n");

	DEBUGP("DADDY: %d: %s\n", s, uaddr.sun_path);
	if (bind(s, (struct sockaddr *) &uaddr, sizeof(uaddr)) != 0)
		PERROR("bind() failed");

	if (listen(s, 1) < 0)
		PERROR("listen() failed");

	prev = s;
	for (i = 0 ; i < n ; i++) {
		int fd = accept(s, (struct sockaddr *)&client, &addrlen);

		if (fd == -1)
			PERROR("accept()");

		if (fd != prev+1)
			ERROR("accept: Not linear! fd=%d needed but got fd=%d\n", prev+1, fd);

		if (controlfd == -1) {
			controlfd = fd;
			DEBUGP("Master socket is %d\n", controlfd);
                }
		prev=fd;
	}
}

void link_sockets(const char *dir, unsigned int n) {
	unsigned int i, ok;
	struct sockaddr_un uaddr;
	size_t ret;
	int s, prev;

        prev = open("/dev/null", O_RDONLY);

	uaddr.sun_family = AF_UNIX;
	ret = snprintf(uaddr.sun_path, sizeof(uaddr.sun_path),
		       "%s/sockets", dir);
	
	if (ret >= sizeof(uaddr.sun_path))
		ERROR("Unix socket's pathname is truncated.\n");

	for (i = 0 ; i < n ; i++) {
		s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (!s)
			PERROR("Cannot allocate another socket");

		if (s != prev+1)
			ERROR("connect: Not linear! fd=%d needed but got fd=%d\n", prev+1, s);
		prev = s;

		do {
			ok = 0;

			if (connect(s, (struct sockaddr *) &uaddr, sizeof(uaddr))) {
				if (errno == ENOENT || errno == ECONNREFUSED) {
                                        sleep(0.1);
					continue;
				} else
					PERROR("connect()");
			}

			ok = 1;
		} while (!ok);
	}
}

void close_sockets(int last, unsigned int n) {
	int i;

	for (i = last+1 ; i < n+last+1 ; i++) {
		if (close(i) != 0)
			PERROR("close()");
	}
}

void jail_exec(const char *socketdir, int argc, char **argv, char **environ) {
	bind_sockets(socketdir, STDERR_FILENO, 0x10 /* XXX */);
	init_memory(0xf000);
	enter_seccomp_mode();
	hijack_vdso_gate();
	(*realmain)(argc, argv, environ);
}

void start_trusted_process(const char *socketdir, pid_t pid)
{
	char *new_argv[] = {  MASTER_DAEMON, "XXXXXXXXXX", NULL};
	char *new_env[] = { NULL };
	char *tmp = malloc(12);

	if (!tmp)
		PERROR("malloc()");
	snprintf(tmp, 12, "%u", pid);
	tmp[sizeof tmp - 1] = '\0';
	new_argv[1] = tmp;

	link_sockets(socketdir, 0x10 /* XXX */);
	execve(MASTER_DAEMON, new_argv, new_env);
	PERROR("execve()");
}
