#include "records/heartbeat.h"

#include "core/buf.h"

#define DTL_HEARTBEAT_SIZE 8u /* u32 + u32 */

dtl_err dtl_heartbeat_parse(const uint8_t *val, size_t len,
                            dtl_arena *a, dtl_heartbeat *out)
{
    dtl_buf b;
    dtl_err rc;

    (void)a;

    if (len != DTL_HEARTBEAT_SIZE)
        return DTL_ERR_BADRECORD;

    dtl_buf_init(&b, val, len);
    if ((rc = dtl_buf_read_u32(&b, &out->uptime_s)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u32(&b, &out->seq)) != DTL_OK)
        return rc;

    return DTL_OK;
}
