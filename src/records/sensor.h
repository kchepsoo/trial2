#ifndef DTL_RECORDS_SENSOR_H
#define DTL_RECORDS_SENSOR_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * REC_SENSOR (tag 0x11) -- variable-length float sample vector.
 *   u16 sensor_id
 *   u8  count
 *   f32 samples[count]   (little-endian IEEE-754, 4 bytes each)
 *
 * The payload must be exactly sensor_id(2) + count(1) + count*4 bytes; any other
 * length is DTL_ERR_BADRECORD. Sample bytes are read as u32 LE then bit-copied
 * into float with memcpy (no type punning), so decoding is UB-free.
 */
typedef struct dtl_sensor {
    uint16_t sensor_id;
    uint8_t  count;
    float   *samples; /* arena-allocated; NULL when count == 0 */
} dtl_sensor;

dtl_err dtl_sensor_parse(const uint8_t *val, size_t len,
                         dtl_arena *a, dtl_sensor *out);

#endif /* DTL_RECORDS_SENSOR_H */
