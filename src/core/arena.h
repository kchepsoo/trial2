#ifndef DTL_CORE_ARENA_H
#define DTL_CORE_ARENA_H

#include <stddef.h>
#include <stdint.h>

/*
 * core/arena -- a growable bump/region allocator for parsed records.
 *
 * The arena hands out aligned chunks of memory that all share a single lifetime:
 * individual allocations are never freed on their own. Storage is organised as a
 * list of malloc'd blocks. Allocation bumps a cursor within the current block;
 * when a request does not fit, a fresh block is added and the block-descriptor
 * array is grown with realloc. Because the user-data blocks themselves are never
 * moved, pointers returned by dtl_arena_alloc stay valid until dtl_arena_reset
 * or dtl_arena_free is called -- this is the correct, memory-safe baseline.
 *
 *   dtl_arena_reset : keep the allocated blocks but rewind every cursor, so the
 *                     memory is reused on the next round of allocations.
 *   dtl_arena_free  : release all blocks and the descriptor array; the arena is
 *                     left empty and may be reused (or re-init'd) afterwards.
 */

typedef struct dtl_arena_block {
    uint8_t *data;  /* malloc'd slab                         */
    size_t   cap;   /* slab capacity in bytes                */
    size_t   used;  /* bytes handed out from this slab       */
} dtl_arena_block;

typedef struct dtl_arena {
    dtl_arena_block *blocks;      /* array of blocks (grown via realloc)      */
    size_t           nblocks;     /* number of live blocks                    */
    size_t           blocks_cap;  /* capacity of the blocks array             */
    size_t           block_size;  /* default slab size for new blocks         */
} dtl_arena;

/*
 * dtl_arena_init -- prepare an empty arena. block_size is the default size for
 * newly allocated slabs; pass 0 to accept an internal default. No memory is
 * allocated until the first dtl_arena_alloc.
 */
void dtl_arena_init(dtl_arena *a, size_t block_size);

/*
 * dtl_arena_alloc -- return a pointer to n bytes, suitably aligned for any
 * scalar type, or NULL if n is 0 or an underlying allocation fails. The bytes
 * are uninitialised. The pointer is valid until the next reset/free of a.
 */
void *dtl_arena_alloc(dtl_arena *a, size_t n);

/*
 * dtl_arena_reset -- rewind all blocks to empty without releasing them. Every
 * pointer previously returned by dtl_arena_alloc is invalidated.
 */
void dtl_arena_reset(dtl_arena *a);

/*
 * dtl_arena_free -- release every block and the descriptor array, returning the
 * arena to the empty, freshly-init'd state (block_size is preserved).
 */
void dtl_arena_free(dtl_arena *a);

#endif /* DTL_CORE_ARENA_H */
