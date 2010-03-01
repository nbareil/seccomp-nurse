#include <unistd.h>
#include <linux/types.h>
#include <errno.h>

#include "helper.h"
#include "common.h"
#include "mm.h"

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

ssize_t poke_memory_request(const int fd, const struct memory_op_msg * req) {
	return fxread(fd, req->addr, req->len);
}

ssize_t peek_memory_request(const int fd, const struct memory_op_msg * req) {
	return write(fd, req->addr, req->len);
}

int wait_for_orders(const int fd) {
        struct memory_op_msg req;
	int msgtype;
	char buf[512];
	ssize_t ret = -1;
	char *addr;

	while (1) {
		fxread(fd, &msgtype, sizeof msgtype);
	
		switch (msgtype) {
		case PEEK_ASCIIZ:
			fxread(fd, &addr, sizeof addr);
			peek_asciiz_request(fd, addr);
			break;

                case PEEK_MEMORY:
			ret = fxread(fd, &req, sizeof req);
			peek_memory_request(fd, &req);
                        break;

                case POKE_MEMORY:
			ret = fxread(fd, &req, sizeof req);
			poke_memory_request(fd, &req);
			break;

		case RETVAL:
			fxread(fd, &ret, sizeof ret);
			fxread(fd, &errno, sizeof errno);
			return ret;

		case NATIVE_EXIT:
			fxread(fd, &ret, sizeof ret);
			_exit(ret);
			break;

                case MEMORY_POOL:
			DEBUGP("big_memory_pool = %#p\n", big_memory_pool);
			write(fd, &big_memory_pool, sizeof big_memory_pool);
			break;

		default:
			ERROR("Unknown message type %x\n", msgtype);
			break;
		}
	}
}
