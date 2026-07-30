#include "core/arena.h"

#include <stdlib.h>


/*
 * AddressSanitizer manual poisoning: every sub-allocation carved from a slab is
 * surrounded by a poisoned redzone, so a small overflow past an arena buffer is
 * caught by ASan instead of silently landing in the next sub-allocation. This is
 * a complete no-op when ASan is not active -- normal and MSan builds allocate
 * with exactly the same layout as before.
 */
#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define DTL_ASAN 1
#  endif
#endif
#if !defined(DTL_ASAN) && defined(__SANITIZE_ADDRESS__)
#  define DTL_ASAN 1
#endif
#if DTL_ASAN
#  include <sanitizer/asan_interface.h>
#endif

/* Bytes of poisoned redzone appended after every sub-allocation (ASan only). */
#define DTL_ARENA_REDZONE 16u

/*
 * Alignment applied to every allocation. 16 bytes is enough for any scalar type
 * this toolkit stores (including 64-bit integers and doubles) and matches the
 * guarantee of the underlying malloc, so pointers into a slab are always usable
 * for aligned access.
 */
#define DTL_ARENA_ALIGN      16u

/* Default slab size when the caller passes block_size == 0. */
#define DTL_ARENA_DEFAULT_BLOCK  4096u

/* Initial capacity of the block-descriptor array on first growth. */
#define DTL_ARENA_MIN_BLOCKS  4u

/* Round n up to a multiple of DTL_ARENA_ALIGN; return 0 if that would wrap. */
static size_t dtl_arena_align_up(size_t n)
{
    size_t rem;

    if (n > SIZE_MAX - (DTL_ARENA_ALIGN - 1u))
        return 0; /* overflow */
    rem = n % DTL_ARENA_ALIGN;
    if (rem != 0)
        n += DTL_ARENA_ALIGN - rem;
    return n;
}

void dtl_arena_init(dtl_arena *a, size_t block_size)
{
    a->blocks = NULL;
    a->nblocks = 0;
    a->blocks_cap = 0;
    a->block_size = block_size ? block_size : DTL_ARENA_DEFAULT_BLOCK;
}

/* Ensure the descriptor array has room for at least one more block. */
static int dtl_arena_reserve_slot(dtl_arena *a)
{
    size_t newcap;
    dtl_arena_block *grown;

    if (a->nblocks < a->blocks_cap)
        return 1;

    newcap = a->blocks_cap ? a->blocks_cap * 2u : DTL_ARENA_MIN_BLOCKS;

    /* Guard the multiplication in the realloc size computation. */
    if (newcap > SIZE_MAX / sizeof(dtl_arena_block))
        return 0;

    grown = realloc(a->blocks, newcap * sizeof(dtl_arena_block));
    if (grown == NULL)
        return 0;

    a->blocks = grown;
    a->blocks_cap = newcap;
    return 1;
}

void *dtl_arena_alloc(dtl_arena *a, size_t n)
{
    size_t need;
    size_t cap;
    uint8_t *data;
    dtl_arena_block *blk;

    if (n == 0)
        return NULL;

    need = dtl_arena_align_up(n);
    if (need == 0)
        return NULL; /* request too large to align */

#if DTL_ASAN
    /* ASan: each sub-allocation is trailed by a poisoned redzone, so the space
     * charged against the slab is need + redzone. */
    need += DTL_ARENA_REDZONE;
#endif

    /* Fast path: does the current (last) block have room? */
    if (a->nblocks != 0) {
        blk = &a->blocks[a->nblocks - 1];
        if (blk->cap - blk->used >= need) {
            data = blk->data + blk->used;
            blk->used += need;
#if DTL_ASAN
            /* The slab is poisoned wholesale; unpoison exactly the n bytes
             * handed to the caller. The alignment padding and the redzone
             * that follow stay poisoned. */
            ASAN_UNPOISON_MEMORY_REGION(data, n);
#endif
            return data;
        }
    }

    /* Otherwise add a new block sized to hold at least this request. */
    cap = need > a->block_size ? need : a->block_size;

    if (!dtl_arena_reserve_slot(a))
        return NULL;

    data = malloc(cap);
    if (data == NULL)
        return NULL;

    blk = &a->blocks[a->nblocks];
    blk->data = data;
    blk->cap = cap;
    blk->used = need;
    a->nblocks += 1;

#if DTL_ASAN
    ASAN_POISON_MEMORY_REGION(data, cap);
    ASAN_UNPOISON_MEMORY_REGION(data, n);
#endif

    return data;
}

void dtl_arena_reset(dtl_arena *a)
{
    size_t i;

    for (i = 0; i < a->nblocks; i++) {
        a->blocks[i].used = 0;
#if DTL_ASAN
        /* The whole slab is unallocated again: re-poison it so reused arenas
         * keep the redzone guarantee. */
        ASAN_POISON_MEMORY_REGION(a->blocks[i].data, a->blocks[i].cap);
#endif
    }
}

void dtl_arena_free(dtl_arena *a)
{
    size_t i;

    for (i = 0; i < a->nblocks; i++) {
#if DTL_ASAN
        /* Freeing poisoned memory is itself an ASan error: unpoison first. */
        ASAN_UNPOISON_MEMORY_REGION(a->blocks[i].data, a->blocks[i].cap);
#endif
        free(a->blocks[i].data);
    }
    free(a->blocks);

    a->blocks = NULL;
    a->nblocks = 0;
    a->blocks_cap = 0;
    /* block_size is preserved so the arena can be reused as-is. */
}
