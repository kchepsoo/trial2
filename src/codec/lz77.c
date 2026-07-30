#include "codec/lz77.h"

#include "defects.h"

#define DTL_LZ77_WINDOW    4096u   /* max back-reference distance */
#define DTL_LZ77_MIN_MATCH 3u      /* shortest match worth encoding */
#define DTL_LZ77_MAX_MATCH 18u     /* 4-bit length field: (len-3) in 0..15 */

/*
 * Greedy longest-match search for the input at position p, restricted to the
 * preceding window. Returns the best match length (0 if none reaches
 * MIN_MATCH) and, when nonzero, its distance back from p in *best_off.
 */
static size_t dtl_lz77_find(const uint8_t *in, size_t in_len, size_t p,
                            size_t *best_off)
{
    size_t start = (p > DTL_LZ77_WINDOW) ? p - DTL_LZ77_WINDOW : 0;
    size_t maxlen = in_len - p;
    size_t best_len = 0;
    size_t s;

    if (maxlen > DTL_LZ77_MAX_MATCH)
        maxlen = DTL_LZ77_MAX_MATCH;

    for (s = start; s < p; s++) {
        size_t l = 0;
        while (l < maxlen && in[s + l] == in[p + l])
            l++;
        if (l > best_len) {
            best_len = l;
            *best_off = p - s;
            if (l == maxlen)
                break; /* cannot do better within this group */
        }
    }

    if (best_len < DTL_LZ77_MIN_MATCH)
        return 0;
    return best_len;
}

dtl_err dtl_lz77_encode(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t p = 0;
    size_t o = 0;
    uint8_t group[1u + 8u * 2u]; /* flag byte + up to 8 two-byte tokens */
    size_t group_len = 1;
    unsigned tokens = 0;
    uint8_t flag = 0;

    while (p < in_len) {
        size_t off = 0;
        size_t len = dtl_lz77_find(in, in_len, p, &off);

        if (len >= DTL_LZ77_MIN_MATCH) {
            uint32_t off_field = (uint32_t)(off - 1);          /* 0..4095 */
            uint32_t len_field = (uint32_t)(len - DTL_LZ77_MIN_MATCH); /* 0..15 */
            flag |= (uint8_t)(1u << tokens);
            group[group_len++] = (uint8_t)(off_field & 0xffu);
            group[group_len++] = (uint8_t)(((off_field >> 8) << 4) | len_field);
            p += len;
        } else {
            group[group_len++] = in[p];
            p += 1;
        }
        tokens++;

        if (tokens == 8) {
            if (out_cap - o < group_len)
                return DTL_ERR_RANGE;
            group[0] = flag;
            for (size_t k = 0; k < group_len; k++)
                out[o + k] = group[k];
            o += group_len;
            group_len = 1;
            tokens = 0;
            flag = 0;
        }
    }

    if (tokens != 0) {
        if (out_cap - o < group_len)
            return DTL_ERR_RANGE;
        group[0] = flag;
        for (size_t k = 0; k < group_len; k++)
            out[o + k] = group[k];
        o += group_len;
    }

    *out_len = o;
    return DTL_OK;
}

dtl_err dtl_lz77_decode(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t i = 0;
    size_t o = 0;

    while (i < in_len) {
        uint8_t flag = in[i++];
        unsigned bit;

        for (bit = 0; bit < 8; bit++) {
            if (i >= in_len)
                break; /* clean end at a token boundary */

            if ((flag >> bit) & 1u) {
                uint8_t b0;
                uint8_t b1;
                size_t offset;
                size_t length;
                size_t src;
                size_t k;

                if (in_len - i < 2)
                    return DTL_ERR_TRUNCATED; /* match token half-present */
                b0 = in[i++];
                b1 = in[i++];

                offset = (size_t)b0 | ((size_t)(b1 >> 4) << 8);
                offset += 1;                               /* 1..4096 */
                length = (size_t)(b1 & 0x0fu) + DTL_LZ77_MIN_MATCH; /* 3..18 */

                /* Back-reference must stay inside what we have written. The
                 * offset == 0 arm is a deliberate tripwire: it is unreachable in
                 * the current two-byte encoding (offset is off_field + 1 >= 1),
                 * but kept so a future change to offset derivation cannot let a
                 * zero-distance reference slip through unchecked. */
#if DTL_BUG(5)
                /* BUG 5: off-by-one bound -- a back-reference one byte before
                 * the start of the output (offset == o + 1) is accepted and
                 * reads out[-1]. */
                if (offset == 0 || offset > o + 1)
                    return DTL_ERR_BADRECORD;
#else
                if (offset == 0 || offset > o)
                    return DTL_ERR_BADRECORD;
#endif
                if (out_cap - o < length)
                    return DTL_ERR_RANGE;

#if DTL_BUG(31)
                /* BUG 31: the back-reference source is computed one byte too
                 * late, so every match reconstructs from the wrong position;
                 * the stream stays structurally valid and nothing bounds
                 * checks fail -- the decoded bytes are simply wrong. */
                src = o - offset + 1;
#else
                src = o - offset;
#endif
                for (k = 0; k < length; k++)
                    out[o + k] = out[src + k]; /* byte-by-byte: overlap-safe */
                o += length;
            } else {
                if (out_cap - o < 1)
                    return DTL_ERR_RANGE;
                out[o++] = in[i++];
            }
        }
    }

    *out_len = o;
    return DTL_OK;
}
