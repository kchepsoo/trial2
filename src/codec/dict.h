#ifndef DTL_CODEC_DICT_H
#define DTL_CODEC_DICT_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * codec/dict (id 4) -- dictionary/token codec with a self-describing table.
 *
 * Encoded blob layout, little-endian:
 *   entry_count u16
 *   entry_count times: phrase_len u8, then phrase_len phrase bytes
 *   token stream: u16 ids, each < entry_count
 * Decode emits, in order, the phrase named by each token id.
 *
 * Decode is strict: a token id >= entry_count is rejected (DTL_ERR_BADRECORD),
 * a table or token that runs past in_len is DTL_ERR_TRUNCATED, and phrase
 * emission is bounds-checked against out_cap (DTL_ERR_RANGE). The entry table is
 * built in a private arena that is released on every return path.
 *
 * The encoder partitions the input into fixed-size blocks and de-duplicates
 * identical blocks into table entries, so repeated phrases share one id.
 */
dtl_err dtl_dict_decode(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_cap, size_t *out_len);
dtl_err dtl_dict_encode(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* DTL_CODEC_DICT_H */
