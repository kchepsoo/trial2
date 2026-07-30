#ifndef DTL_CODEC_RLE_H
#define DTL_CODEC_RLE_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * codec/rle (id 1) -- byte run-length coding.
 *
 * Encoded form is a sequence of [count u8][value u8] pairs, count in 1..255;
 * each pair denotes `count` repetitions of `value`. Encode coalesces runs
 * (splitting runs longer than 255). Decode expands them, checking the output
 * cursor against out_cap before each run so it can never overrun the buffer.
 * A zero count is rejected (DTL_ERR_BADRECORD); an odd-length input, where a
 * trailing count has no value byte, is DTL_ERR_TRUNCATED.
 */
dtl_err dtl_rle_decode(const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);
dtl_err dtl_rle_encode(const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* DTL_CODEC_RLE_H */
