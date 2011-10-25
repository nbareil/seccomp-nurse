#include <unistd.h>
#include <linux/types.h>
#include <errno.h>
#include "helper.h"
#include "companion.h"
#include "common.h"
#include "mm.h"

struct memory_op_msg {
	__u32 addr;
	__u32 len;
};

ssize_t peek_asciiz_request(int fd, char *start) {
	char * ptr = start;
	__u32 i = 0;

	while (*ptr++)
		i++;

	xwrite(fd, &i, sizeof i);
	return xwrite(fd, start, i);
}

ssize_t poke_memory_request(int fd, struct memory_op_msg * req) {
	ssize_t ret;
	size_t bytesread;
	char *ptr = (char *)req->addr;

	while (bytesread < req->len) {
		ret = xread(fd, ptr, req->len - bytesread);
		if (ret < 0) {
			PERROR("poke_memory/read failed:");
		}
		ptr += ret;
		bytesread += ret;
	}
	return bytesread;
}

ssize_t peek_memory_request(int fd, struct memory_op_msg * req) {
	return (ssize_t)xwrite(fd, (void *)req->addr, req->len);
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
                        asm("mov $1, %%eax\n"
                            "mov %0, %%ebx\n"
                            "int $0x80\n"
                            : /* output */
                            : "m" (ret));
			break;

                case RAISE_TRAP:
			asm("int3\n");
			break;

		default:
			ERROR("Unknown message type %x\n", msgtype);
			break;
		}
	}
}
