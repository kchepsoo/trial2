// codec_fuzzer -- first byte selects a codec from the registry (the same
// dispatch the container parser uses); the rest of the input is treated as an
// encoded blob and decoded, then re-encoded and decoded again when the first
// decode succeeds (round-trip through codec encode/decode).
#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" {
#include "codec/registry.h"
}

static const size_t kMaxBuf = 4u * 1024u * 1024u;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == nullptr || size < 2)
        return 0;

    const dtl_codec *codec = dtl_codec_get(data[0] % 7);
    if (codec == nullptr)
        return 0;

    const uint8_t *in = data + 1;
    size_t in_len = size - 1;

    size_t cap1 = in_len * 8 + 64;
    if (cap1 > kMaxBuf)
        cap1 = kMaxBuf;
    uint8_t *raw = (uint8_t *)malloc(cap1);
    if (raw == nullptr)
        return 0;
    size_t raw_len = 0;

    if (codec->decode(in, in_len, raw, cap1, &raw_len) == DTL_OK &&
        raw_len > 0) {
        size_t cap2 = raw_len * 2 + 64;
        uint8_t *re = (uint8_t *)malloc(cap2);
        uint8_t *back = (uint8_t *)malloc(cap1);
        if (re != nullptr && back != nullptr) {
            size_t re_len = 0, back_len = 0;
            if (codec->encode(raw, raw_len, re, cap2, &re_len) == DTL_OK &&
                re_len > 0)
                (void)codec->decode(re, re_len, back, cap1, &back_len);
        }
        free(re);
        free(back);
    }

    free(raw);
    return 0;
}
