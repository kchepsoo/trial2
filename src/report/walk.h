#ifndef DTL_REPORT_WALK_H
#define DTL_REPORT_WALK_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"
#include "records/record.h"

/*
 * report/walk -- shared container-traversal pipeline used by the reporting
 * tools (stats, validate, index, export, diff, merge, split).
 *
 * A walk opens a container, decodes every section with its declared codec,
 * walks the decompressed TLV stream, parses each record, and invokes the
 * caller's callback once per record, in wire order. Records are parsed into a
 * caller-visible arena whose lifetime covers the whole walk, so a callback
 * may retain the dtl_record structs it is handed (the pointers inside them
 * stay valid until the walk's arena is freed).
 *
 * A record that fails TLV framing or typed parsing is reported through the
 * optional on_error callback; the walk ends that section's stream, since the
 * framing cursor cannot be trusted past a malformed length.
 */

typedef struct dtl_walk_event {
    uint16_t          section_type;   /* type id from the section table       */
    uint8_t           codec_id;       /* codec the section blob was stored as */
    uint16_t          section_index;  /* 0-based position in the table        */
    size_t            record_in_sec;  /* 0-based record number in the section */
    size_t            record_index;   /* global 0-based record number         */
    const dtl_record *rec;            /* parsed record (arena-owned)          */
} dtl_walk_event;

typedef struct dtl_walk_error {
    uint16_t section_index;
    size_t   record_in_sec;
    dtl_err  rc;          /* the failure that was encountered                */
    int      fatal;       /* nonzero when the section stream was abandoned   */
} dtl_walk_error;

/* Return DTL_OK to continue the walk, anything else to abort with that code. */
typedef dtl_err (*dtl_walk_fn)(const dtl_walk_event *ev, void *user);
typedef void (*dtl_walk_error_fn)(const dtl_walk_error *we, void *user);

typedef struct dtl_walk {
    dtl_walk_fn       on_record;  /* required                                */
    dtl_walk_error_fn on_error;   /* optional (NULL drops error reports)     */
    void             *user;
    /* Decode cap per section, guarding against adversarial raw_len values. */
    size_t            max_decode; /* 0 selects the default (16 MiB)          */
} dtl_walk;

/*
 * dtl_walk_memory -- walk a container held in memory. The arena a must
 * outlive the callback's use of any retained records; the walk allocates the
 * section array, decode scratch, and record payloads from it.
 */
dtl_err dtl_walk_memory(const uint8_t *data, size_t len, dtl_arena *a,
                        const dtl_walk *w);

/*
 * dtl_walk_file -- read path (size-capped at max_file bytes) into a private
 * arena and walk it. Records handed to the callback remain valid until the
 * call returns; retain copies, not pointers, past that point.
 */
dtl_err dtl_walk_file(const char *path, size_t max_file, const dtl_walk *w);

/*
 * dtl_walk_absorb -- like dtl_walk_file, but reads into the caller's arena
 * a instead of a private one. Records (and their payloads) stay valid until
 * the caller frees a, so the callback may retain them. Use this when the
 * records must outlive the walk (merge/split).
 */
dtl_err dtl_walk_absorb(const char *path, size_t max_file, dtl_arena *a,
                        const dtl_walk *w);

/* dtl_walk_tag_name -- stable printable name for a record tag. */
const char *dtl_walk_tag_name(uint8_t tag);

#endif /* DTL_REPORT_WALK_H */
