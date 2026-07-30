#ifndef DTL_RECORDS_KEYREF_H
#define DTL_RECORDS_KEYREF_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * REC_KEYREF (tag 0x19) -- reference to a keystore slot plus a human label.
 *   u8 slot_id
 *   u8 label_len
 *   char label[label_len]   (NOT null-terminated on the wire)
 *
 * label_len is bounded by the remaining bytes: a label that runs past the TLV
 * is DTL_ERR_TRUNCATED, and trailing bytes after the label are DTL_ERR_BADRECORD.
 * The label is copied into the arena and null-terminated. slot_id is stored
 * verbatim; the crypto module resolves it against the keystore later.
 */
typedef struct dtl_keyref {
    uint8_t     slot_id;
    uint8_t     label_len;
    const char *label;    /* arena-allocated, null-terminated */
    uint8_t     redacted; /* set by the redaction pass; 0 after parse */
} dtl_keyref;

dtl_err dtl_keyref_parse(const uint8_t *val, size_t len,
                         dtl_arena *a, dtl_keyref *out);

#endif /* DTL_RECORDS_KEYREF_H */
