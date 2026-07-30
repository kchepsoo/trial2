#ifndef DTL_RECORDS_FIRMWARE_H
#define DTL_RECORDS_FIRMWARE_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * REC_FIRMWARE (tag 0x1A) -- fixed 14-byte payload.
 *   u16 major
 *   u16 minor
 *   u16 patch
 *   u8  hash[8]
 */
typedef struct dtl_firmware {
    uint16_t major;
    uint16_t minor;
    uint16_t patch;
    uint8_t  hash[8];
} dtl_firmware;

dtl_err dtl_firmware_parse(const uint8_t *val, size_t len,
                           dtl_arena *a, dtl_firmware *out);

#endif /* DTL_RECORDS_FIRMWARE_H */
