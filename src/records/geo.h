#ifndef DTL_RECORDS_GEO_H
#define DTL_RECORDS_GEO_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * REC_GEO (tag 0x14) -- fixed 12-byte payload; fixed-point coordinates.
 *   i32 lat_e7   (degrees * 1e7)
 *   i32 lon_e7   (degrees * 1e7)
 *   i32 alt_mm   (millimetres)
 */
typedef struct dtl_geo {
    int32_t lat_e7;
    int32_t lon_e7;
    int32_t alt_mm;
} dtl_geo;

dtl_err dtl_geo_parse(const uint8_t *val, size_t len,
                      dtl_arena *a, dtl_geo *out);

#endif /* DTL_RECORDS_GEO_H */
