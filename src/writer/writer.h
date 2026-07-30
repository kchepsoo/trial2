#ifndef DTL_WRITER_WRITER_H
#define DTL_WRITER_WRITER_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"
#include "records/record.h"

/*
 * writer/writer -- the DTL encoder: the exact inverse of the decode pipeline.
 *
 * Usage is incremental:
 *   dtl_writer_init(w, arena);
 *   h = dtl_writer_begin_section(w, type, codec_id);
 *       dtl_writer_add_record(w, &rec);   // one or more, any of the 11 types
 *   dtl_writer_end_section(w);            // compresses the section's TLV stream
 *   ... more sections ...
 *   dtl_writer_set_hmac(w, key, klen);    // optional
 *   dtl_writer_finish(w, &bytes, &len);   // emits the whole container
 *
 * Everything is arena-allocated (including the output). The emitted bytes parse
 * cleanly back through dtl_container_parse + the section codec + the record
 * parsers. The writer latches the first error it hits; later calls become no-ops
 * and dtl_writer_finish returns that error.
 */

/* Maximum number of sections a single log may contain. */
#define DTL_WRITER_MAX_SECTIONS 64

typedef struct dtl_wsection {
    uint16_t       type;
    uint8_t        codec_id;
    uint32_t       raw_len;  /* decompressed TLV stream length */
    uint32_t       comp_len; /* compressed blob length */
    const uint8_t *blob;     /* comp_len compressed bytes (arena) */
} dtl_wsection;

typedef struct dtl_writer {
    dtl_arena   *arena;
    dtl_wsection sections[DTL_WRITER_MAX_SECTIONS];
    size_t       nsections;

    int          in_section;
    uint16_t     cur_type;
    uint8_t      cur_codec;

    /* Accumulator for the current section's raw TLV stream (grows in arena). */
    uint8_t     *tlv;
    size_t       tlv_len;
    size_t       tlv_cap;

    int            has_hmac;
    const uint8_t *hmac_key;
    size_t         hmac_key_len;

    dtl_err      err; /* first error latched, or DTL_OK */
} dtl_writer;

/* Start an empty log. */
void dtl_writer_init(dtl_writer *w, dtl_arena *a);

/*
 * Begin a section with the given type and codec. Returns a non-negative section
 * handle (its index), or -1 on error (already in a section, too many sections,
 * or a prior latched error).
 */
int dtl_writer_begin_section(dtl_writer *w, uint16_t type, uint8_t codec_id);

/* Encode one record and append it to the current section's TLV stream. */
dtl_err dtl_writer_add_record(dtl_writer *w, const dtl_record *rec);

/*
 * Append a TLV with a caller-supplied tag/len/payload verbatim, bypassing the
 * typed encoders. In this correct reference it simply writes well-formed TLV
 * bytes; it exists so tests can build inputs (including deliberately malformed
 * records, later) procedurally.
 */
dtl_err dtl_writer_add_raw_tlv(dtl_writer *w, uint8_t tag,
                               const uint8_t *payload, uint16_t len);

/*
 * Append `count` fixed-stride u32 telemetry points as one TLV payload. The
 * points are staged contiguously first so the payload lands in the TLV
 * accumulator with a single copy; the payload cap (u16 length prefix) limits
 * the batch to 0xFFFF / 4 points.
 */
dtl_err dtl_writer_add_u32_batch(dtl_writer *w, uint8_t tag,
                                 const uint32_t *vals, uint32_t count);

/* Compress the accumulated TLV stream with the section's codec and record it. */
dtl_err dtl_writer_end_section(dtl_writer *w);

/* Request an HMAC trailer over header+table+blobs, keyed by key. */
dtl_err dtl_writer_set_hmac(dtl_writer *w, const uint8_t *key, size_t key_len);

/*
 * Emit the whole container into an arena-allocated buffer. On success sets *out
 * and *out_len and returns DTL_OK; otherwise returns the latched error.
 */
dtl_err dtl_writer_finish(dtl_writer *w, uint8_t **out, size_t *out_len);

#endif /* DTL_WRITER_WRITER_H */
