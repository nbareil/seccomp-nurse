#include "mm.h"

mspace mm = NULL;

void init_memory(size_t mem)
{
	mm = create_mspace(mem, 0);
}

static void * my_malloc_hook(size_t size, const void *caller)
{
	return mspace_malloc(mm, size);
}

static void * my_free_hook(void *ptr, const void *caller)
{
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

