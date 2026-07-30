#include "records/firmware.h"

#include "core/buf.h"

#define DTL_FIRMWARE_SIZE 14u /* u16 * 3 + u8[8] */
#define DTL_FIRMWARE_HASH_LEN 8u

dtl_err dtl_firmware_parse(const uint8_t *val, size_t len,
                           dtl_arena *a, dtl_firmware *out)
{
    dtl_buf b;
    dtl_err rc;

    (void)a;

    if (len != DTL_FIRMWARE_SIZE)
        return DTL_ERR_BADRECORD;

    dtl_buf_init(&b, val, len);
    if ((rc = dtl_buf_read_u16(&b, &out->major)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u16(&b, &out->minor)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u16(&b, &out->patch)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_bytes(&b, out->hash, DTL_FIRMWARE_HASH_LEN)) != DTL_OK)
        return rc;

    return DTL_OK;
}
