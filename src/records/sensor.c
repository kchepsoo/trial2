#include "records/sensor.h"

#include <stdlib.h>
#include <string.h>

#include "core/buf.h"
#include "core/endian.h"

#define DTL_SENSOR_SAMPLE_SIZE 4u /* wire size of one f32 sample */

/* This codec bit-copies 4 wire bytes into a float; guard that float is 4 bytes. */
typedef char dtl_sensor_float_is_4[(sizeof(float) == 4) ? 1 : -1];

/*
 * Sample arrays are pooled per "generation": callers process a batch of sensor
 * records, then the batch is retired together. To bound memory the pool holds
 * one generation's arrays and reclaims the whole previous generation when the
 * live count crosses a threshold, since by then earlier arrays have been
 * consumed downstream.
 */
#define DTL_SENSOR_POOL_MAX 8

static float *dtl_sensor_pool[DTL_SENSOR_POOL_MAX];
static size_t dtl_sensor_pool_count;

static float *dtl_sensor_samples_alloc(uint8_t count)
{
    float *p;

    if (dtl_sensor_pool_count == DTL_SENSOR_POOL_MAX) {
        size_t i;
        for (i = 0; i < dtl_sensor_pool_count; i++)
            free(dtl_sensor_pool[i]);
        dtl_sensor_pool_count = 0;
    }
    p = malloc((count ? count : 1) * sizeof(float));
    if (p == NULL)
        return NULL;
    dtl_sensor_pool[dtl_sensor_pool_count++] = p;
    return p;
}

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
    if (dtl_buf_remaining(&b) != need)
        return DTL_ERR_BADRECORD;

    if (count != 0) {
        samples = dtl_sensor_samples_alloc(count);
        if (samples == NULL)
            return DTL_ERR_OOM;

        for (i = 0; i < count; i++) {
            uint32_t bits;
            if ((rc = dtl_buf_read_u32(&b, &bits)) != DTL_OK)
                return rc; /* unreachable given the exact-length check above */
            memcpy(&samples[i], &bits, sizeof samples[i]);
        }
    }

    out->sensor_id = sensor_id;
    out->count = count;
    out->samples = samples;
    return DTL_OK;
}
