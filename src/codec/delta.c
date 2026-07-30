#include "codec/delta.h"


#include "core/endian.h"

#define DTL_DELTA_LAST_SHIFT 28 /* fifth LEB128 group carries only 4 bits of a u32 */

/* Zig-zag map a 32-bit two's-complement delta to an unsigned value, no signed ops. */
static uint32_t dtl_delta_zigzag(uint32_t d)
{
    return (d << 1) ^ (0u - (d >> 31));
}

/* Inverse zig-zag. */
static uint32_t dtl_delta_unzigzag(uint32_t z)
{
    return (z >> 1) ^ (0u - (z & 1u));
}

dtl_err dtl_delta_encode(const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t n;
    size_t k;
    size_t o = 0;
    uint32_t prev;

    if (in_len == 0) {
        *out_len = 0;
        return DTL_OK;
    }
    if (in_len % 4 != 0)
        return DTL_ERR_TRUNCATED; /* trailing partial u32 */

    n = in_len / 4;

    prev = dtl_endian_read_u32le(in);
    if (out_cap - o < 4)
        return DTL_ERR_RANGE;
    dtl_endian_write_u32le(out + o, prev);
    o += 4;

    for (k = 1; k < n; k++) {
        uint32_t cur = dtl_endian_read_u32le(in + k * 4);
        uint32_t zz = dtl_delta_zigzag(cur - prev); /* wraps in uint32 */

        do {
            uint8_t byte = (uint8_t)(zz & 0x7fu);
            zz >>= 7;
            if (zz != 0)
                byte |= 0x80u;
            if (out_cap - o < 1)
                return DTL_ERR_RANGE;
            out[o++] = byte;
        } while (zz != 0);

        prev = cur;
    }

    *out_len = o;
    return DTL_OK;
}

dtl_err dtl_delta_decode(const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t i;
    size_t o = 0;
    uint32_t prev;

    if (in_len == 0) {
        *out_len = 0;
        return DTL_OK;
    }
    if (in_len < 4)
        return DTL_ERR_TRUNCATED; /* first raw value incomplete */

    prev = dtl_endian_read_u32le(in);
    if (out_cap - o < 4)
        return DTL_ERR_RANGE;
    dtl_endian_write_u32le(out + o, prev);
    o += 4;

    i = 4;
    while (i < in_len) {
        uint32_t zz = 0;
        int shift = 0;
        uint32_t d;
        uint32_t cur;

        for (;;) {
            uint8_t byte;
            uint32_t payload;

            if (i >= in_len)
                return DTL_ERR_TRUNCATED;
            byte = in[i++];

            if (shift > DTL_DELTA_LAST_SHIFT)
                return DTL_ERR_RANGE;
            payload = (uint32_t)(byte & 0x7fu);
            if (shift == DTL_DELTA_LAST_SHIFT && payload > 0x0fu)
                return DTL_ERR_RANGE;

            zz |= payload << shift;

            if ((byte & 0x80u) == 0)
                break;
            shift += 7;
        }

        d = dtl_delta_unzigzag(zz);
        cur = prev + d; /* wraps in uint32 */

        if (out_cap - o < 4)
            return DTL_ERR_RANGE;
        dtl_endian_write_u32le(out + o, cur);
        o += 4;
        prev = cur;
    }

    *out_len = o;
    return DTL_OK;
}
