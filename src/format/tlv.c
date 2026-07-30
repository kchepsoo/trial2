#include "format/tlv.h"

dtl_err dtl_tlv_next(dtl_buf *stream, dtl_tlv *out)
{
    uint8_t tag;
    uint16_t len;
    dtl_err rc;

    if ((rc = dtl_buf_read_u8(stream, &tag)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u16(stream, &len)) != DTL_OK)
        return rc;

    /*
     * The payload length comes only from the len field, and is validated
     * against the stream's remaining bytes by subtraction -- never by forming
     * pos + len, which could wrap. If the declared payload does not fit, the
     * record is truncated and no payload byte is touched.
     */
    if ((size_t)len > dtl_buf_remaining(stream))
        return DTL_ERR_TRUNCATED;

    out->tag = tag;
    out->len = len;
    out->val = stream->p + stream->pos;
    stream->pos += len;
    return DTL_OK;
}

dtl_err dtl_tlv_count(const dtl_buf *stream, size_t *out_count)
{
    dtl_buf tmp = *stream; /* iterate a copy; caller's cursor is untouched */
    size_t n = 0;

    while (dtl_buf_remaining(&tmp) != 0) {
        dtl_tlv rec;
        dtl_err rc = dtl_tlv_next(&tmp, &rec);
        if (rc != DTL_OK) {
            *out_count = n;
            return rc;
        }
        n++;
    }

    *out_count = n;
    return DTL_OK;
}
