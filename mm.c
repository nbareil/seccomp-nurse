#include <sys/mman.h>

#include "mm.h"
#include "common.h"
#include "helper.h"

mspace mm = NULL;
void *big_memory_pool;

void init_memory(size_t mem)
{


	mm = create_mspace(mem, 0);
	big_memory_pool = mmap(NULL, 
			       0xf000,
			       PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
			       -1, 0);

	if (!big_memory_pool)
                _exit(1);
}

static void * my_malloc_hook(size_t size, const void *caller)
{
	DEBUGP("malloc(%d)", size);
	return mspace_malloc(mm, size);
}

static void * my_free_hook(void *ptr, const void *caller)
{
	DEBUGP("free()");
        mspace_free(mm, ptr);
	return NULL;
}

static void my_malloc_init(void)
{
	char *ptr1, *ptr2;

	old_malloc_hook = __malloc_hook;
	old_free_hook = __free_hook;

	__malloc_hook = my_malloc_hook;
	__free_hook = my_free_hook;
}

/* void (*__malloc_initialize_hook) (void) = my_malloc_init; */

