#include "records/sensor.h"

#include <string.h>

#include "core/buf.h"
#include "core/endian.h"
#include "defects.h"

#define DTL_SENSOR_SAMPLE_SIZE 4u /* wire size of one f32 sample */

/* This codec bit-copies 4 wire bytes into a float; guard that float is 4 bytes. */
typedef char dtl_sensor_float_is_4[(sizeof(float) == 4) ? 1 : -1];

dtl_err dtl_sensor_parse(const uint8_t *val, size_t len,
                         dtl_arena *a, dtl_sensor *out)
{
    dtl_buf b;
    uint16_t sensor_id;
    uint8_t count;
    size_t need;
    size_t i;
    float *samples = NULL;
    dtl_err rc;

    dtl_buf_init(&b, val, len);

    if ((rc = dtl_buf_read_u16(&b, &sensor_id)) != DTL_OK)
        return rc;
    if ((rc = dtl_buf_read_u8(&b, &count)) != DTL_OK)
        return rc;

    /* count <= 255, so count*4 cannot overflow size_t. Require an exact fit. */
    need = (size_t)count * DTL_SENSOR_SAMPLE_SIZE;
#if !DTL_BUG(9)
    if (dtl_buf_remaining(&b) != need)
        return DTL_ERR_BADRECORD;
#endif

    if (count != 0) {
        samples = dtl_arena_alloc(a, (size_t)count * sizeof(float));
        if (samples == NULL)
            return DTL_ERR_OOM;

        for (i = 0; i < count; i++) {
            uint32_t bits;
#if DTL_BUG(9)
            /* BUG 9: no payload-length check -- a record declaring more
             * samples than the payload holds reads past the TLV value. */
            bits = dtl_endian_read_u32le(b.p + b.pos);
            b.pos += DTL_SENSOR_SAMPLE_SIZE;
#else
            if ((rc = dtl_buf_read_u32(&b, &bits)) != DTL_OK)
                return rc; /* unreachable given the exact-length check above */
#endif
            memcpy(&samples[i], &bits, sizeof samples[i]);
        }
    }

    out->sensor_id = sensor_id;
    out->count = count;
    out->samples = samples;
    return DTL_OK;
}
