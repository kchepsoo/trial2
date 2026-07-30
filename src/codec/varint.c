#include "codec/varint.h"

#include "core/endian.h"
#include "defects.h"

/*
 * A u32 needs at most five 7-bit groups. The final (fifth) group carries only
 * the top 4 bits, so at shift 28 the payload must be <= 0x0f; a sixth
 * continuation byte (which would push shift past 28) overflows the 32-bit range.
 */
#define DTL_VARINT_LAST_SHIFT 28

dtl_err dtl_varint_decode(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t i = 0;
    size_t o = 0;

    while (i < in_len) {
        uint32_t value = 0;
        int shift = 0;

        for (;;) {
            uint8_t byte;
            uint32_t payload;

#if DTL_BUG(7)
            /* BUG 7: no in-bounds check -- a varint whose final byte has the
             * continuation bit set keeps reading past in_len. */
            byte = in[i++];
#else
            if (i >= in_len)
                return DTL_ERR_TRUNCATED; /* continuation with no next byte */
            byte = in[i++];
#endif

            /* A group beyond the fifth cannot fit in a u32. */
            if (shift > DTL_VARINT_LAST_SHIFT)
                return DTL_ERR_RANGE;
            payload = (uint32_t)(byte & 0x7fu);
            if (shift == DTL_VARINT_LAST_SHIFT && payload > 0x0fu)
                return DTL_ERR_RANGE;

            value |= payload << shift;

            if ((byte & 0x80u) == 0)
                break;
            shift += 7;
        }

        if (out_cap - o < 4)
            return DTL_ERR_RANGE;
        dtl_endian_write_u32le(out + o, value);
        o += 4;
    }

    *out_len = o;
    return DTL_OK;
}

dtl_err dtl_varint_encode(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t i = 0;
    size_t o = 0;

    while (i < in_len) {
        uint32_t value;

        if (in_len - i < 4)
            return DTL_ERR_TRUNCATED; /* trailing partial u32 */
        value = dtl_endian_read_u32le(in + i);
        i += 4;

        /* Emit 7 bits at a time, low group first; high bit flags "more". */
        do {
            uint8_t byte = (uint8_t)(value & 0x7fu);
            value >>= 7;
            if (value != 0)
                byte |= 0x80u;
            if (out_cap - o < 1)
                return DTL_ERR_RANGE;
            out[o++] = byte;
        } while (value != 0);
    }

    *out_len = o;
    return DTL_OK;
}
