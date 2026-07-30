#ifndef DTL_CODEC_VARINT_H
#define DTL_CODEC_VARINT_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * codec/varint (id 2) -- LEB128 unsigned varint stream codec.
 *
 * Decode reads a sequence of LEB128 varints and emits each as a fixed 4-byte
 * little-endian u32. Encode reads fixed 4-byte little-endian u32 values and
 * emits their LEB128 encodings.
 *
 * Decode is strict: every continuation byte is bounds-checked, so a varint left
 * without a terminator before in_len yields DTL_ERR_TRUNCATED and never reads
 * past the input; a varint whose value would exceed 32 bits yields
 * DTL_ERR_RANGE. Encode requires the input length to be a multiple of 4 (a
 * trailing partial u32 is DTL_ERR_TRUNCATED). Neither direction writes past
 * out_cap (DTL_ERR_RANGE).
 */
dtl_err dtl_varint_decode(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len);
dtl_err dtl_varint_encode(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* DTL_CODEC_VARINT_H */
