#ifndef DTL_RECORDS_LOG_H
#define DTL_RECORDS_LOG_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * REC_LOG (tag 0x17) -- severity-tagged log line.
 *   u8  severity      (0..7; >7 rejected as DTL_ERR_BADRECORD)
 *   u16 msg_len
 *   char msg[msg_len] (NOT null-terminated on the wire)
 *
 * msg_len must equal the bytes remaining after the header, else BADRECORD. The
 * message is copied into an arena buffer of msg_len + 1 bytes and null-
 * terminated, so dtl_log.msg is always a valid C string.
 */
typedef struct dtl_log {
    uint8_t     severity;
    uint16_t    msg_len;
    const char *msg; /* arena-allocated, null-terminated */
} dtl_log;

dtl_err dtl_log_parse(const uint8_t *val, size_t len,
                      dtl_arena *a, dtl_log *out);

#endif /* DTL_RECORDS_LOG_H */
