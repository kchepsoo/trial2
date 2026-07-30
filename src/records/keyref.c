#include "records/keyref.h"

#include "core/buf.h"

dtl_err dtl_keyref_parse(const uint8_t *val, size_t len,
                         dtl_arena *a, dtl_keyref *out)
{
    dtl_buf b;
    uint8_t slot_id;
    uint8_t label_len;
    char *label;
    dtl_err rc;

    dtl_buf_init(&b, val, len);

    if ((rc = dtl_buf_read_u8(&b, &slot_id)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u8(&b, &label_len)) != DTL_OK)
        return rc;

    label = dtl_arena_alloc(a, (size_t)label_len + 1);
    if (label == NULL)
        return DTL_ERR_OOM;
    if ((rc = dtl_buf_read_bytes(&b, label, label_len)) != DTL_OK)
        return rc; /* label runs past the TLV */
    label[label_len] = '\0';

    /* The label must consume the rest of the payload exactly. */
    if (dtl_buf_remaining(&b) != 0)
        return DTL_ERR_BADRECORD;

    out->slot_id = slot_id;
    out->label_len = label_len;
    out->label = label;
    out->redacted = 0;
    return DTL_OK;
}
