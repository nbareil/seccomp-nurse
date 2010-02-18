enum {
	DO_SYSCALL = 1,
	PEEK_ASCIIZ,
	PEEK_MEMORY,
	POKE_MEMORY,
	RETVAL,
	NATIVE_EXIT,
        MEMORY_POOL,
};

static int controlfd = -1;
