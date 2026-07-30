#ifndef DTL_CODEC_LZ77_H
#define DTL_CODEC_LZ77_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * codec/lz77 (id 3) -- LZ77 over a bounded 4096-byte sliding window.
 *
 * The token stream is grouped: a flag byte precedes each run of up to 8 tokens,
 * bit i (LSB first) selecting match (1) or literal (0) for token i. A literal is
 * one byte. A match is two bytes encoding a 12-bit (offset-1) in 1..4096 and a
 * 4-bit (length-3) in 3..18; decode copies length bytes from out_pos - offset
 * one byte at a time, so overlapping matches reproduce correctly.
 *
 * Decode is strict: a match offset of 0 or one larger than the bytes written so
 * far is rejected (DTL_ERR_BADRECORD) so it can never read before the output
 * start; every literal and match byte is checked against out_cap (DTL_ERR_RANGE)
 * and every token byte against in_len (DTL_ERR_TRUNCATED).
 */
dtl_err dtl_lz77_decode(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_cap, size_t *out_len);
dtl_err dtl_lz77_encode(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* DTL_CODEC_LZ77_H */
