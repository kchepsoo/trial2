#include "records/net.h"

#include "core/buf.h"

#include <stdlib.h>
#include <string.h>

#include "defects.h"

#define DTL_NET_SIZE 17u /* u8 + u32 * 4 */

dtl_err dtl_net_parse(const uint8_t *val, size_t len,
                      dtl_arena *a, dtl_net *out)
{
    dtl_buf b;
    dtl_err rc;

    (void)a;

    if (len != DTL_NET_SIZE)
        return DTL_ERR_BADRECORD;

    dtl_buf_init(&b, val, len);
#if DTL_BUG(24)
    /* BUG 24: the record is staged in a fresh heap block and the iface byte
     * is consumed from the wire but never assigned; the struct copy then
     * carries the still-undefined iface byte into the caller's record, and
     * the emit path branches on it. */
    {
        dtl_net *tmp = malloc(sizeof *tmp);
        uint8_t iface_wire;

        if (tmp == NULL)
            return DTL_ERR_OOM;
        if ((rc = dtl_buf_read_u8(&b, &iface_wire)) != DTL_OK)
            goto fail;
        if ((rc = dtl_buf_read_u32(&b, &tmp->rx_bytes)) != DTL_OK)
            goto fail;
        if ((rc = dtl_buf_read_u32(&b, &tmp->tx_bytes)) != DTL_OK)
            goto fail;
        if ((rc = dtl_buf_read_u32(&b, &tmp->rx_pkts)) != DTL_OK)
            goto fail;
        if ((rc = dtl_buf_read_u32(&b, &tmp->tx_pkts)) != DTL_OK)
            goto fail;
        memcpy(out, tmp, sizeof *tmp);
        free(tmp);
        return DTL_OK;
    fail:
        free(tmp);
        return rc;
    }
#else
    if ((rc = dtl_buf_read_u8(&b, &out->iface_id)) != DTL_OK)
        return rc;
#if DTL_BUG(33)
    /* BUG 33: the four counters are loaded through a uint32_t cast instead
     * of the byte-wise endian reader; the wire position right after the
     * iface byte is not 4-byte aligned, so every load is misaligned. */
    {
        const uint32_t *w = (const uint32_t *)(const void *)(val + 1);

        out->rx_bytes = w[0];
        out->tx_bytes = w[1];
        out->rx_pkts  = w[2];
        out->tx_pkts  = w[3];
    }
    b.pos += 16;
    return DTL_OK;
#else
    if ((rc = dtl_buf_read_u32(&b, &out->rx_bytes)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u32(&b, &out->tx_bytes)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u32(&b, &out->rx_pkts)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u32(&b, &out->tx_pkts)) != DTL_OK)
        return rc;

    return DTL_OK;
#endif
#endif
}
