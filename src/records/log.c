#include "records/log.h"

#include "core/buf.h"


#define DTL_LOG_SEVERITY_MAX 7u

dtl_err dtl_log_parse(const uint8_t *val, size_t len,
                      dtl_arena *a, dtl_log *out)
{
    dtl_buf b;
    uint8_t severity;
    uint16_t msg_len;
    char *msg;
    dtl_err rc;

    dtl_buf_init(&b, val, len);

    if ((rc = dtl_buf_read_u8(&b, &severity)) != DTL_OK)
        return rc;
    if (severity > DTL_LOG_SEVERITY_MAX)
        return DTL_ERR_BADRECORD;
    if ((rc = dtl_buf_read_u16(&b, &msg_len)) != DTL_OK)
        return rc;

    if ((size_t)msg_len != dtl_buf_remaining(&b))
        return DTL_ERR_BADRECORD;

    /* +1 for the terminator we add; msg_len <= 65535 so this cannot overflow. */
    msg = dtl_arena_alloc(a, (size_t)msg_len + 1);
    if (msg == NULL)
        return DTL_ERR_OOM;
    if ((rc = dtl_buf_read_bytes(&b, msg, msg_len)) != DTL_OK)
        return rc;
    msg[msg_len] = '\0';

    out->severity = severity;
    out->msg_len = msg_len;
    out->msg = msg;
    return DTL_OK;
}
