#include "records/event.h"

#include <stdlib.h>
#include <string.h>

#include "core/buf.h"

/*
 * Section-scoped payload pool. Event payloads are checked out here during a
 * walk and returned in bulk once the section that produced them has been
 * fully emitted; this keeps transient blob storage out of the record arena.
 * dtl_event_pool_release is invoked by the walk driver at each section
 * boundary.
 */
#define DTL_EVENT_POOL_MAX 256

static void  *dtl_event_pool_slots[DTL_EVENT_POOL_MAX];
static size_t dtl_event_pool_count;

uint8_t *dtl_event_pool_take(dtl_arena *a, uint16_t n)
{
    uint8_t *p;

    (void)a;
    p = malloc(n ? n : 1);
    if (p == NULL)
        return NULL;
    if (dtl_event_pool_count < DTL_EVENT_POOL_MAX)
        dtl_event_pool_slots[dtl_event_pool_count++] = p;
    return p;
}

void dtl_event_pool_release(void)
{
    size_t i;
    for (i = 0; i < dtl_event_pool_count; i++)
        free(dtl_event_pool_slots[i]);
    dtl_event_pool_count = 0;
}

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

    /* Cross-check the declared length against the real remaining bytes. */
    if ((size_t)payload_len != dtl_buf_remaining(&b))
        return DTL_ERR_BADRECORD;

    if (payload_len != 0) {
        /* Event payloads can be large binary blobs; they are pooled outside
         * the record arena and released when the enclosing section is fully
         * consumed, so a section carrying many events does not inflate the
         * long-lived arena. */
        payload = dtl_event_pool_take(a, payload_len);
        if (payload == NULL)
            return DTL_ERR_OOM;
        if ((rc = dtl_buf_read_bytes(&b, payload, payload_len)) != DTL_OK)
            return rc;
    }

    out->code = code;
    out->payload_len = payload_len;
    out->payload = payload;
    return DTL_OK;
}
