#include "core/buf.h"

#include <string.h>

#include "core/endian.h"

void dtl_buf_init(dtl_buf *b, const uint8_t *p, size_t len)
{
    b->p = p;
    b->len = len;
    b->pos = 0;
}

size_t dtl_buf_remaining(const dtl_buf *b)
{
    /* Invariant pos <= len is upheld by init and every read below. */
    return b->len - b->pos;
}

dtl_err dtl_buf_read_bytes(dtl_buf *b, void *out, size_t n)
{
    size_t avail = b->len - b->pos;

    /*
     * Compare against remaining bytes by subtraction only; never form pos + n,
     * which could wrap for a hostile n near SIZE_MAX.
     */
    if (n > avail)
        return DTL_ERR_TRUNCATED;

    if (n != 0)
        memcpy(out, b->p + b->pos, n);
    b->pos += n;
    return DTL_OK;
}

dtl_err dtl_buf_read_u8(dtl_buf *b, uint8_t *out)
{
    if (b->len - b->pos < 1)
        return DTL_ERR_TRUNCATED;

    *out = b->p[b->pos];
    b->pos += 1;
    return DTL_OK;
}

dtl_err dtl_buf_read_u16(dtl_buf *b, uint16_t *out)
{
    if (b->len - b->pos < 2)
        return DTL_ERR_TRUNCATED;

    *out = dtl_endian_read_u16le(b->p + b->pos);
    b->pos += 2;
    return DTL_OK;
}

dtl_err dtl_buf_read_u32(dtl_buf *b, uint32_t *out)
{
    if (b->len - b->pos < 4)
        return DTL_ERR_TRUNCATED;

    *out = dtl_endian_read_u32le(b->p + b->pos);
    b->pos += 4;
    return DTL_OK;
}

dtl_err dtl_buf_read_u64(dtl_buf *b, uint64_t *out)
{
    if (b->len - b->pos < 8)
        return DTL_ERR_TRUNCATED;

    *out = dtl_endian_read_u64le(b->p + b->pos);
    b->pos += 8;
    return DTL_OK;
}
