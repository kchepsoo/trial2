#ifndef DTL_RECORDS_BATTERY_H
#define DTL_RECORDS_BATTERY_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * REC_BATTERY (tag 0x15) -- fixed 7-byte payload.
 *   u8  pct
 *   i16 temp_c_e1   (degrees C * 10)
 *   u32 cycles
 */
typedef struct dtl_battery {
    uint8_t  pct;
    int16_t  temp_c_e1;
    uint32_t cycles;
} dtl_battery;

dtl_err dtl_battery_parse(const uint8_t *val, size_t len,
                          dtl_arena *a, dtl_battery *out);

#endif /* DTL_RECORDS_BATTERY_H */
