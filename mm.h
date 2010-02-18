#ifndef __MM_H

#define __MM_H

#define MSPACES 1
#define ONLY_MSPACES 1
#define USE_DL_PREFIX 1
#define DEBUG 1

#include "dlmalloc.h"

extern void (*__after_morecore_hook)(void);
extern void (*__malloc_initialize_hook) (void);
extern void (*__free_hook)(void *, const void *);
extern void *(*__malloc_hook)(size_t,  __const void *);
extern void *(*__realloc_hook)(void *, size_t, __const void *);
extern void *(*__memalign_hook)(size_t, size_t, __const void *);

void (*old_after_morecore_hook)(void);
void (*old_malloc_initialize_hook) (void);
void (*old_free_hook)(void *, __const void *);
void *(*old_malloc_hook)(size_t,  __const void *);
void *(*old_realloc_hook)(void *, size_t, __const void *);
void *(*old_memalign_hook)(size_t, size_t, __const void *);

static void my_malloc_init(void);

#define XCHANGE_VALUE(a, b) do { typeof(a) c = a; a = b; b = c; } while (0);

#endif
