#ifndef DTL_CORE_BUF_H
#define DTL_CORE_BUF_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * core/buf -- a bounded, forward-only reader over an immutable byte span.
 *
 * A dtl_buf borrows a caller-owned region [p, p+len) and tracks a read cursor
 * pos in [0, len]. Every read is bounds-checked against len before any byte is
 * touched: a read that would pass the end returns DTL_ERR_TRUNCATED, consumes
 * nothing, and leaves the cursor unmoved. Nothing here ever reads past len.
 *
 * This is the choke point the rest of the toolkit trusts for input safety, so
 * the checks are written to be correct even at the extremes of size_t (no
 * `pos + n` additions that could wrap -- comparisons are framed as subtraction
 * against the known-valid remaining count).
 */

typedef struct dtl_buf {
    const uint8_t *p;   /* start of the borrowed region (not owned)          */
    size_t         len; /* number of readable bytes at p                     */
    size_t         pos; /* cursor: bytes already consumed, invariant pos<=len*/
} dtl_buf;

/*
 * dtl_buf_init -- bind a reader to [p, p+len) with the cursor at the start.
 * A len of 0 is allowed (p may then be NULL); every read will report
 * truncation.
 */
void dtl_buf_init(dtl_buf *b, const uint8_t *p, size_t len);

/* dtl_buf_remaining -- unread bytes, i.e. len - pos. */
size_t dtl_buf_remaining(const dtl_buf *b);

/*
 * dtl_buf_read_bytes -- copy the next n bytes into out and advance the cursor.
 * out must have room for n bytes; n == 0 always succeeds. On truncation the
 * cursor is unchanged and out is left untouched.
 */
dtl_err dtl_buf_read_bytes(dtl_buf *b, void *out, size_t n);

/*
 * Fixed-width little-endian reads. Each consumes the width on success, writes
 * the decoded value through the out pointer, and reports DTL_ERR_TRUNCATED
 * (leaving the cursor put) if fewer than that many bytes remain.
 */
dtl_err dtl_buf_read_u8(dtl_buf *b, uint8_t *out);
dtl_err dtl_buf_read_u16(dtl_buf *b, uint16_t *out);
dtl_err dtl_buf_read_u32(dtl_buf *b, uint32_t *out);
dtl_err dtl_buf_read_u64(dtl_buf *b, uint64_t *out);

#endif /* DTL_CORE_BUF_H */
