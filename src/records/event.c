#include "records/event.h"

#include <string.h>

#include "core/buf.h"
#include "defects.h"

dtl_err dtl_event_parse(const uint8_t *val, size_t len,
                        dtl_arena *a, dtl_event *out)
{
    dtl_buf b;
    uint16_t code;
    uint16_t payload_len;
    uint8_t *payload = NULL;
    dtl_err rc;

    dtl_buf_init(&b, val, len);

    if ((rc = dtl_buf_read_u16(&b, &code)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u16(&b, &payload_len)) != DTL_OK)
        return rc;

#if DTL_BUG(28)
    /* BUG 28 (decoder half): the declared payload_len is trusted without a
     * cross-check against the real remaining bytes, so a mis-framed stream
     * (see writer.c) drives a copy that reads past the backing buffer. */
    if (payload_len != 0) {
        payload = dtl_arena_alloc(a, payload_len);
        if (payload == NULL)
            return DTL_ERR_OOM;
        memcpy(payload, b.p + b.pos, payload_len);
        b.pos += payload_len;
    }
#else
    /* Cross-check the declared length against the real remaining bytes. */
    if ((size_t)payload_len != dtl_buf_remaining(&b))
        return DTL_ERR_BADRECORD;

    if (payload_len != 0) {
        payload = dtl_arena_alloc(a, payload_len);
        if (payload == NULL)
            return DTL_ERR_OOM;
        if ((rc = dtl_buf_read_bytes(&b, payload, payload_len)) != DTL_OK)
            return rc;
    }
#endif

    out->code = code;
    out->payload_len = payload_len;
    out->payload = payload;
    return DTL_OK;
}
