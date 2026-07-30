#ifndef DTL_FORMAT_TLV_H
#define DTL_FORMAT_TLV_H

#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"
#include "core/err.h"

/*
 * format/tlv -- tag/length/value record framing within a (decompressed) section
 * stream.
 *
 * Each record on the wire is:
 *     tag  u8
 *     len  u16   (little-endian; a varint length codec arrives later)
 *     val  len bytes
 *
 * The value is borrowed: dtl_tlv.val points into the stream buffer, valid for
 * the lifetime of that buffer. The payload length is taken solely from the len
 * field and checked strictly against the bytes remaining in the stream, so a
 * record can never reach past the stream's end.
 */

typedef struct dtl_tlv {
    uint8_t        tag;
    uint16_t       len;
    const uint8_t *val;  /* -> len bytes inside the stream buffer */
} dtl_tlv;

/*
 * dtl_tlv_next -- read the next record from stream and advance its cursor.
 * Returns DTL_OK and fills *out on success. Returns DTL_ERR_TRUNCATED if the
 * header or the declared payload runs past the end of the stream. On success
 * out->val references len bytes inside the stream buffer.
 */
dtl_err dtl_tlv_next(dtl_buf *stream, dtl_tlv *out);

/*
 * dtl_tlv_count -- count the whole records in stream without disturbing it.
 * Iterates a private copy. Returns DTL_OK with *out_count set to the number of
 * records if the stream ends exactly on a record boundary; otherwise returns
 * the error from the offending record, with *out_count set to the number of
 * complete records read before it.
 */
dtl_err dtl_tlv_count(const dtl_buf *stream, size_t *out_count);

#endif /* DTL_FORMAT_TLV_H */
