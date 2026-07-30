#ifndef DTL_RECORDS_DIAG_H
#define DTL_RECORDS_DIAG_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * REC_DIAG (tag 0x13) -- opaque diagnostic blob with an in-payload length.
 *   u16 subsystem
 *   u16 blob_len
 *   u8  blob[blob_len]
 *
 * Like REC_EVENT, the declared blob_len is cross-checked against the bytes
 * actually remaining in the TLV; a mismatch in either direction is
 * DTL_ERR_BADRECORD. The blob copy is bounded by the real TLV remaining, never
 * by blob_len on its own, and is stored in the arena.
 */
typedef struct dtl_diag {
    uint16_t       subsystem;
    uint16_t       blob_len;
    const uint8_t *blob;     /* arena-allocated; NULL when blob_len == 0 */
    uint8_t        redacted; /* set by the redaction pass; 0 after parse */
} dtl_diag;

dtl_err dtl_diag_parse(const uint8_t *val, size_t len,
                       dtl_arena *a, dtl_diag *out);

#endif /* DTL_RECORDS_DIAG_H */
