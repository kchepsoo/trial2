#ifndef DTL_CODEC_BASE32_H
#define DTL_CODEC_BASE32_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * codec/base32 (id 6) -- RFC 4648 base32 (uppercase A-Z, 2-7; '=' padding).
 *
 * Encode maps each group of 5 input bytes to 8 characters, padding a short final
 * group with '=' (1/2/3/4 trailing bytes -> 6/4/3/1 pad chars). Decode reverses
 * it: the input length must be a multiple of 8 (else DTL_ERR_TRUNCATED), any
 * character outside the alphabet or a '=' in a data position is rejected
 * (DTL_ERR_BADRECORD), an invalid padding count is rejected (DTL_ERR_BADRECORD),
 * and output is bounds-checked against out_cap (DTL_ERR_RANGE).
 */
dtl_err dtl_base32_decode(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len);
dtl_err dtl_base32_encode(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* DTL_CODEC_BASE32_H */
