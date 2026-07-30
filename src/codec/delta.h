#ifndef DTL_CODEC_DELTA_H
#define DTL_CODEC_DELTA_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * codec/delta (id 5) -- delta + zig-zag codec over a u32 stream.
 *
 * The decoded form is a sequence of little-endian u32 values (4 bytes each).
 * Encode stores the first value as a raw 4-byte LE word, then each subsequent
 * value as the zig-zag-mapped LEB128 varint of its delta from the previous
 * value. Decode reverses this.
 *
 * All delta and reconstruction arithmetic is done in uint32_t (wrapping is
 * well-defined) and zig-zag mapping uses only unsigned operations, so there is
 * no signed overflow or implementation-defined shift. Encode requires the input
 * length to be a multiple of 4 (a trailing partial word is DTL_ERR_TRUNCATED);
 * decode reports DTL_ERR_TRUNCATED on a varint with no terminator, DTL_ERR_RANGE
 * on a delta that overflows 32 bits, and DTL_ERR_RANGE on output overrun.
 */
dtl_err dtl_delta_decode(const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len);
dtl_err dtl_delta_encode(const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* DTL_CODEC_DELTA_H */
