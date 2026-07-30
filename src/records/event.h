#ifndef DTL_RECORDS_EVENT_H
#define DTL_RECORDS_EVENT_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * REC_EVENT (tag 0x12) -- coded event with an in-payload length field.
 *   u16 code
 *   u16 payload_len
 *   u8  payload[payload_len]
 *
 * The declared payload_len is cross-checked against the bytes actually
 * remaining in the TLV: if they disagree (in either direction) the record is
 * rejected with DTL_ERR_BADRECORD. The payload is copied into the arena.
 */
typedef struct dtl_event {
    uint16_t       code;
    uint16_t       payload_len;
    const uint8_t *payload; /* arena-allocated; NULL when payload_len == 0 */
} dtl_event;

dtl_err dtl_event_parse(const uint8_t *val, size_t len,
                        dtl_arena *a, dtl_event *out);

#endif /* DTL_RECORDS_EVENT_H */

/* Section-scoped event payload pool (see event.c). */
uint8_t *dtl_event_pool_take(dtl_arena *a, uint16_t n);
void dtl_event_pool_release(void);
