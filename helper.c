#include <unistd.h>
#include <linux/types.h>
#include <errno.h>

#include "helper.h"

struct memory_op_msg {
	__u32 addr;
	__u32 len;
};

ssize_t peek_asciiz_request(const int fd, const char *start) {
	char * ptr = start;
	__u32 i = 0;

	while (*ptr++)
		i++;

	write(fd, &i, sizeof i);
	return write(fd, start, i);
}

ssize_t poke_memory_request(const int fd, const char request[], const size_t reqlen) {
	struct memory_op_msg *req;

	if (reqlen < sizeof(*req))
		return -1;

	req = (struct memory_op_msg *)&request;
	return write(fd, req->addr, req->len);
}

ssize_t peek_memory_request(const int fd, const char request[], const size_t reqlen) {
	struct memory_op_msg *req;

	if (reqlen < sizeof(*req))
		return -1;

	req = (struct memory_op_msg *)&request;
	return read(fd, req->addr, req->len);
}

enum {
	DO_SYSCALL = 1,
	PEEK_ASCIIZ,
	PEEK_MEMORY,
	POKE_MEMORY,
	RETVAL,
	NATIVE_EXIT,
};

int wait_for_orders(const int fd) {
	int msgtype;
	char buf[512];
	ssize_t ret = -1;
	char *addr;

	while (1) {
		ret = read(fd, &msgtype, sizeof msgtype);
		if (ret < 0) {
			perror("read()");
			return -1;
		}

		if (ret != sizeof msgtype)
			return -1;
	
		switch (msgtype) {
		case PEEK_ASCIIZ:
			read(fd, &addr, sizeof addr);
			peek_asciiz_request(fd, addr);
			break;

		case RETVAL:
			read(fd, &ret, sizeof ret);
			read(fd, &errno, sizeof errno);
			return ret;

		case NATIVE_EXIT:
			read(fd, &ret, sizeof ret);
			_exit(ret);
			break;

		default:
			printf("Unknown message type %x\n", msgtype);
			break;
		}
	}
}
