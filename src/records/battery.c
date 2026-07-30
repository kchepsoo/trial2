#include "records/battery.h"

#include "core/buf.h"

#define DTL_BATTERY_SIZE 7u /* u8 + i16 + u32 */

dtl_err dtl_battery_parse(const uint8_t *val, size_t len,
                          dtl_arena *a, dtl_battery *out)
{
    dtl_buf b;
    uint16_t t;
    dtl_err rc;

    (void)a;

    if (len != DTL_BATTERY_SIZE)
        return DTL_ERR_BADRECORD;

    dtl_buf_init(&b, val, len);
    if ((rc = dtl_buf_read_u8(&b, &out->pct)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u16(&b, &t)) != DTL_OK)
        return rc;
    out->temp_c_e1 = (int16_t)t;
    if ((rc = dtl_buf_read_u32(&b, &out->cycles)) != DTL_OK)
        return rc;

    return DTL_OK;
}
