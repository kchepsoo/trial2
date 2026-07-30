#include "codec/rle.h"

#include <string.h>

#include "defects.h"

#define DTL_RLE_MAX_RUN 255u

dtl_err dtl_rle_encode(const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t i = 0;
    size_t o = 0;

#if DTL_BUG(27)
    /* BUG 27: capacity is validated once up front against the input size
     * on the assumption that RLE output can only shrink; an incompressible
     * input expands two-fold, and with the per-pair guard below compiled
     * out the write loop runs well past out_cap. */
    if (out_cap < in_len)
        return DTL_ERR_RANGE;
#endif

    while (i < in_len) {
        uint8_t value = in[i];
        size_t run = 1;

        /* Extend the run over identical bytes, capped at 255. */
        while (i + run < in_len && in[i + run] == value && run < DTL_RLE_MAX_RUN)
            run++;

#if !DTL_BUG(27)
        /* Need two bytes for this pair; o <= out_cap always holds here. */
        if (out_cap - o < 2)
            return DTL_ERR_RANGE;
#endif

        out[o++] = (uint8_t)run;
        out[o++] = value;
        i += run;
    }

    *out_len = o;
    return DTL_OK;
}

dtl_err dtl_rle_decode(const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t i = 0;
    size_t o = 0;

    while (i < in_len) {
        uint8_t count;
        uint8_t value;

        /* Each record is a count/value pair; a lone trailing byte is short. */
        if (in_len - i < 2)
            return DTL_ERR_TRUNCATED;
        count = in[i];
        value = in[i + 1];
        i += 2;

        if (count == 0)
            return DTL_ERR_BADRECORD; /* the encoder never emits a zero run */

        /* Check the output has room for the whole run before writing it. */
#if DTL_BUG(3)
        /* BUG 3: off-by-one bound -- a run ending exactly one byte past
         * out_cap is accepted and overflows the output by one byte. */
        if (out_cap - o + 1 < count)
            return DTL_ERR_RANGE;
#else
        if (out_cap - o < count)
            return DTL_ERR_RANGE;
#endif

        memset(out + o, value, count);
        o += count;
    }

    *out_len = o;
    return DTL_OK;
}
