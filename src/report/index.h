#ifndef DTL_REPORT_INDEX_H
#define DTL_REPORT_INDEX_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * report/index -- a tag index over a DTL container.
 *
 * dtl_index_build walks a container file once and records, for every record,
 * its tag, its section, and its ordinal position. The index answers "where
 * are all records of tag T" without re-decoding the container, and prints a
 * per-tag posting summary.
 *
 * Everything is arena-allocated: build with an arena, use, then free the
 * arena. Posting lists are chunked so a large container does not force one
 * giant allocation.
 */

typedef struct dtl_index_entry {
    uint8_t  tag;
    uint16_t section_index;
    uint32_t record_in_sec;
    uint32_t record_index;   /* global ordinal */
} dtl_index_entry;

typedef struct dtl_index_chunk {
    dtl_index_entry        entries[256];
    size_t                 count;
    struct dtl_index_chunk *next;
} dtl_index_chunk;

typedef struct dtl_index {
    dtl_arena       *a;
    dtl_index_chunk *head;
    dtl_index_chunk *tail;
    size_t           total;
    size_t           per_tag[256];
} dtl_index;

/*
 * dtl_index_build -- build the index for the container at path (size-capped
 * at max_file bytes) into idx, allocating from a.
 */
dtl_err dtl_index_build(const char *path, size_t max_file, dtl_arena *a,
                        dtl_index *idx);

/*
 * dtl_index_foreach_tag -- invoke cb once per entry whose tag equals tag, in
 * build order. Returns the number of matching entries.
 */
size_t dtl_index_foreach_tag(const dtl_index *idx, uint8_t tag,
                             void (*cb)(const dtl_index_entry *e, void *user),
                             void *user);

/* dtl_index_print -- per-tag posting-count summary. */
void dtl_index_print(const dtl_index *idx, FILE *out);

#endif /* DTL_REPORT_INDEX_H */
