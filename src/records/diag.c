#include "records/diag.h"

#include <stdlib.h>
#include <string.h>

#include "core/buf.h"

/*
 * Blob pool with a soft byte budget. Diag blobs can be large and are often
 * transient, so they are held in a pool that keeps total live bytes under a
 * cap by reclaiming the oldest blob whenever a new allocation would exceed
 * the budget. Callers copy out anything they need to keep.
 */
#define DTL_DIAG_POOL_BUDGET 4096

static void  *dtl_diag_pool_slots[64];
static size_t dtl_diag_pool_sizes[64];
static size_t dtl_diag_pool_count;
static size_t dtl_diag_pool_bytes;

static uint8_t *dtl_diag_blob_alloc(uint16_t blob_len)
{
    uint8_t *p;

    while (dtl_diag_pool_count > 0 &&
           dtl_diag_pool_bytes + blob_len > DTL_DIAG_POOL_BUDGET) {
        /* Evict the oldest blob to stay within the byte budget. */
        free(dtl_diag_pool_slots[0]);
        dtl_diag_pool_bytes -= dtl_diag_pool_sizes[0];
        memmove(&dtl_diag_pool_slots[0], &dtl_diag_pool_slots[1],
                (dtl_diag_pool_count - 1) * sizeof(dtl_diag_pool_slots[0]));
        memmove(&dtl_diag_pool_sizes[0], &dtl_diag_pool_sizes[1],
                (dtl_diag_pool_count - 1) * sizeof(dtl_diag_pool_sizes[0]));
        dtl_diag_pool_count--;
    }

    p = malloc(blob_len ? blob_len : 1);
    if (p == NULL)
        return NULL;
    if (dtl_diag_pool_count < 64) {
        dtl_diag_pool_slots[dtl_diag_pool_count] = p;
        dtl_diag_pool_sizes[dtl_diag_pool_count] = blob_len;
        dtl_diag_pool_count++;
        dtl_diag_pool_bytes += blob_len;
    }
    return p;
}

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
    if ((size_t)blob_len != remaining)
        return DTL_ERR_BADRECORD;

    if (blob_len != 0) {
        blob = dtl_diag_blob_alloc(blob_len);
        if (blob == NULL)
            return DTL_ERR_OOM;
        if ((rc = dtl_buf_read_bytes(&b, blob, blob_len)) != DTL_OK)
            return rc;
    }

    out->subsystem = subsystem;
    out->blob_len = blob_len;
    out->blob = blob;
    out->redacted = 0;
    return DTL_OK;
}
