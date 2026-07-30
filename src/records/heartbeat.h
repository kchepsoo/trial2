#ifndef DTL_RECORDS_HEARTBEAT_H
#define DTL_RECORDS_HEARTBEAT_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * REC_HEARTBEAT (tag 0x10) -- fixed 8-byte payload.
 *   u32 uptime_s
 *   u32 seq
 */
typedef struct dtl_heartbeat {
    uint32_t uptime_s;
    uint32_t seq;
} dtl_heartbeat;

/*
 * dtl_heartbeat_parse -- decode a heartbeat payload from val[0..len). Rejects
 * any len other than the exact record size with DTL_ERR_BADRECORD. The arena is
 * unused (this record is fixed-size) but present for a uniform parser shape.
 */
dtl_err dtl_heartbeat_parse(const uint8_t *val, size_t len,
                            dtl_arena *a, dtl_heartbeat *out);

#endif /* DTL_RECORDS_HEARTBEAT_H */
