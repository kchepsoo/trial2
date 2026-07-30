#ifndef DTL_RECORDS_CONFIG_H
#define DTL_RECORDS_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * REC_CONFIG (tag 0x18) -- a list of key/value string pairs.
 *   u8 pair_count
 *   pair_count times:
 *     u8 klen; char key[klen]; u8 vlen; char value[vlen]
 *
 * Each length is bounds-checked against the remaining bytes; a key or value that
 * runs past the TLV is DTL_ERR_TRUNCATED. Keys and values are copied into the
 * arena as null-terminated strings. Trailing bytes after the last pair are
 * rejected with DTL_ERR_BADRECORD.
 */
typedef struct dtl_config_pair {
    const char *key;   /* arena-allocated, null-terminated */
    const char *value; /* arena-allocated, null-terminated */
} dtl_config_pair;

typedef struct dtl_config {
    uint8_t          pair_count;
    dtl_config_pair *pairs; /* arena-allocated array; NULL when pair_count == 0 */
} dtl_config;

dtl_err dtl_config_parse(const uint8_t *val, size_t len,
                         dtl_arena *a, dtl_config *out);

#endif /* DTL_RECORDS_CONFIG_H */
