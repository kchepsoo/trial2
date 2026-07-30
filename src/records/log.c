#include "records/log.h"

#include "core/buf.h"
#include "defects.h"

#if DTL_BUG(6)
#include <stdlib.h>
#endif

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
#if DTL_BUG(6)
    /* BUG 6: the allocation drops the +1 but the terminator is still written
     * at msg[msg_len] -- a one-byte heap overflow write. The buffer is a
     * dedicated tight heap block (not arena-carved), so the write crosses a
     * real malloc redzone and ASan reports a genuine heap-buffer-overflow.
     * Single-shot parse: the block is intentionally not freed here; ownership
     * passes to the caller via out->msg. */
    msg = malloc((size_t)msg_len);
#else
    msg = dtl_arena_alloc(a, (size_t)msg_len + 1);
#endif
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
