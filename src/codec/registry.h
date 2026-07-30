#ifndef DTL_CODEC_REGISTRY_H
#define DTL_CODEC_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * codec/registry -- the codec dispatch table.
 *
 * A codec sits between a stored section blob and its decompressed byte stream.
 * Every codec exposes the same decode/encode shape; decode expands a blob into
 * the raw stream, encode is its inverse. Both are bounds-safe: decode never
 * writes past out_cap (DTL_ERR_RANGE) and never reads past in_len
 * (DTL_ERR_TRUNCATED). On success *out_len holds the number of bytes produced.
 *
 * codec_id 0 is STORE (identity). Ids 1..6 are reserved for the compression
 * codecs; the registry only advertises the ones actually implemented and
 * returns NULL for any id it does not know.
 */

typedef dtl_err (*dtl_codec_fn)(const uint8_t *in, size_t in_len,
                                uint8_t *out, size_t out_cap, size_t *out_len);

typedef struct dtl_codec {
    uint8_t       id;
    const char   *name;
    dtl_codec_fn  decode;
    dtl_codec_fn  encode;
} dtl_codec;

/* Codec ids. */
enum {
    DTL_CODEC_STORE  = 0,
    DTL_CODEC_RLE    = 1,
    DTL_CODEC_VARINT = 2,
    DTL_CODEC_LZ77   = 3,
    DTL_CODEC_DICT   = 4,
    DTL_CODEC_DELTA  = 5,
    DTL_CODEC_BASE32 = 6
};

/*
 * dtl_codec_get -- look up a codec by id. Returns a pointer to a static,
 * immutable descriptor, or NULL if no codec is registered for that id.
 */
const dtl_codec *dtl_codec_get(uint8_t codec_id);

#endif /* DTL_CODEC_REGISTRY_H */
