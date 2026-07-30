#ifndef DTL_CODEC_STORE_H
#define DTL_CODEC_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * codec/store (id 0) -- the identity codec. Decode and encode are the same
 * bounded copy: the bytes are reproduced verbatim, provided they fit within
 * out_cap (else DTL_ERR_RANGE).
 */
dtl_err dtl_store_decode(const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len);
dtl_err dtl_store_encode(const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* DTL_CODEC_STORE_H */
