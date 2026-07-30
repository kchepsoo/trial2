#include "records/net.h"

#include "core/buf.h"

#include <stdlib.h>
#include <string.h>


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
    if ((rc = dtl_buf_read_u8(&b, &out->iface_id)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u32(&b, &out->rx_bytes)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u32(&b, &out->tx_bytes)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u32(&b, &out->rx_pkts)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u32(&b, &out->tx_pkts)) != DTL_OK)
        return rc;

    return DTL_OK;
}
