#include "records/diag.h"

#include <string.h>

#include "core/buf.h"
#include "defects.h"

dtl_err dtl_diag_parse(const uint8_t *val, size_t len,
                       dtl_arena *a, dtl_diag *out)
{
    dtl_buf b;
    uint16_t subsystem;
    uint16_t blob_len;
    size_t remaining;
    uint8_t *blob = NULL;
    dtl_err rc;

    dtl_buf_init(&b, val, len);

    if ((rc = dtl_buf_read_u16(&b, &subsystem)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u16(&b, &blob_len)) != DTL_OK)
        return rc;

    /*
     * Validate the declared blob_len against the real remaining TLV bytes and
     * bound the copy by that remaining count. blob_len alone never drives a
     * read.
     */
    remaining = dtl_buf_remaining(&b);
#if !DTL_BUG(1)
    if ((size_t)blob_len != remaining)
        return DTL_ERR_BADRECORD;
#endif

    if (blob_len != 0) {
        blob = dtl_arena_alloc(a, blob_len);
        if (blob == NULL)
            return DTL_ERR_OOM;
#if DTL_BUG(1)
        /* BUG 1: no cross-check -- an oversized blob_len reads past the TLV
         * payload into adjacent arena memory (which holds the device key). */
        memcpy(blob, b.p + b.pos, blob_len);
        b.pos += blob_len;
        (void)remaining;
#else
        if ((rc = dtl_buf_read_bytes(&b, blob, blob_len)) != DTL_OK)
            return rc;
#endif
    }

    out->subsystem = subsystem;
    out->blob_len = blob_len;
    out->blob = blob;
    out->redacted = 0;
    return DTL_OK;
}
