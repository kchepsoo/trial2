#include "codec/base32.h"

#include <string.h>

#include "defects.h"

/* Encoding alphabet (RFC 4648): index 0..31 -> character. */
static const char dtl_base32_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/* Reverse map char -> 5-bit value, or -1 for anything not in the alphabet. */
static int8_t dtl_base32_rev[256];
static int    dtl_base32_rev_ready = 0;

static void dtl_base32_build_rev(void)
{
    int i;
    for (i = 0; i < 256; i++)
        dtl_base32_rev[i] = -1;
    for (i = 0; i < 32; i++)
        dtl_base32_rev[(unsigned char)dtl_base32_alphabet[i]] = (int8_t)i;
    dtl_base32_rev_ready = 1;
}

/* Significant output characters produced by a final group of b input bytes. */
static const unsigned dtl_base32_chars_for_bytes[6] = { 0, 2, 4, 5, 7, 8 };

dtl_err dtl_base32_encode(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t i = 0;
    size_t o = 0;

    while (i < in_len) {
        size_t b = in_len - i;
        uint64_t acc = 0;
        unsigned chars;
        unsigned j;
        size_t k;

        if (b > 5)
            b = 5;

        for (k = 0; k < b; k++)
            acc |= (uint64_t)in[i + k] << (8u * (4u - k));

        chars = dtl_base32_chars_for_bytes[b];

        if (out_cap - o < 8)
            return DTL_ERR_RANGE;

        for (j = 0; j < 8; j++) {
            if (j < chars)
                out[o++] = (uint8_t)dtl_base32_alphabet[(acc >> (5u * (7u - j))) & 0x1fu];
            else
                out[o++] = (uint8_t)'=';
        }

        i += b;
    }

    *out_len = o;
    return DTL_OK;
}

dtl_err dtl_base32_decode(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t g;
    size_t ngroups;
    size_t o = 0;

    if (!dtl_base32_rev_ready)
        dtl_base32_build_rev();

    if (in_len == 0) {
        *out_len = 0;
        return DTL_OK;
    }
    if (in_len % 8 != 0)
        return DTL_ERR_TRUNCATED; /* base32 is padded to a multiple of 8 */

    ngroups = in_len / 8;

    for (g = 0; g < ngroups; g++) {
        uint8_t grp[8];
        unsigned pad = 0;
        unsigned databytes;
        unsigned datachars;
        uint64_t acc = 0;
        unsigned j;
        size_t k;

        memcpy(grp, in + g * 8, 8);

#if DTL_BUG(18)
        /* BUG 18: the final group's pad scan runs forward with an inclusive
         * bound, so a full (unpadded) final group reads grp[8], one slot
         * past the 8-byte stack scratch. */
        if (g == ngroups - 1) {
            unsigned i = 0;
            while (i <= 8 && grp[i] != '=')
                i++;
            pad = 8u - i;
        } else {
            while (pad < 8 && grp[7 - pad] == '=')
                pad++;
        }
#else
        while (pad < 8 && grp[7 - pad] == '=')
            pad++;
#endif

        /* Padding may only appear in the final group. */
        if (g != ngroups - 1 && pad != 0)
            return DTL_ERR_BADRECORD;

        switch (pad) {
        case 0: databytes = 5; break;
        case 1: databytes = 4; break;
        case 3: databytes = 3; break;
        case 4: databytes = 2; break;
        case 6: databytes = 1; break;
        default: return DTL_ERR_BADRECORD; /* 2/5/7 pad chars are illegal */
        }
        datachars = 8u - pad;

        for (j = 0; j < datachars; j++) {
            int v = dtl_base32_rev[grp[j]];
            if (v < 0)
                return DTL_ERR_BADRECORD; /* invalid char, or '=' in data area */
            acc |= (uint64_t)v << (5u * (7u - j));
        }

#if DTL_BUG(15)
        /* BUG 15: the output bound is a 32-bit decoded-size estimate derived
         * from the input length -- ngroups*5 wraps for a large input, the
         * wrapped estimate replaces the caller's real capacity, and the write
         * loop runs past the caller's buffer. */
        {
            uint32_t est = (uint32_t)(ngroups * 5u);

            if (est - (uint32_t)o < databytes)
                return DTL_ERR_RANGE;
        }
#else
        if (out_cap - o < databytes)
            return DTL_ERR_RANGE;
#endif
#if DTL_BUG(8)
        /* BUG 8: padding miscount -- a 6-pad group yields only 1 data byte,
         * but this branch writes 2, overflowing a correctly sized buffer. */
        if (pad == 6)
            databytes = 2;
#endif
        for (k = 0; k < databytes; k++)
            out[o++] = (uint8_t)((acc >> (8u * (4u - k))) & 0xffu);
    }

    *out_len = o;
    return DTL_OK;
}
