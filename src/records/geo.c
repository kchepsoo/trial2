#include "records/geo.h"

#include "core/buf.h"

#define DTL_GEO_SIZE 12u /* i32 * 3 */

dtl_err dtl_geo_parse(const uint8_t *val, size_t len,
                      dtl_arena *a, dtl_geo *out)
{
    dtl_buf b;
    uint32_t v;
    dtl_err rc;

    (void)a;

    if (len != DTL_GEO_SIZE)
        return DTL_ERR_BADRECORD;

    dtl_buf_init(&b, val, len);
    if ((rc = dtl_buf_read_u32(&b, &v)) != DTL_OK)
        return rc;
    out->lat_e7 = (int32_t)v;
    if ((rc = dtl_buf_read_u32(&b, &v)) != DTL_OK)
        return rc;
    out->lon_e7 = (int32_t)v;
    if ((rc = dtl_buf_read_u32(&b, &v)) != DTL_OK)
        return rc;
    out->alt_mm = (int32_t)v;

    return DTL_OK;
}
