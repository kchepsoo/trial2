#include "codec/rle.h"

#include <string.h>


#define DTL_RLE_MAX_RUN 255u

dtl_err dtl_rle_encode(const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t i = 0;
    size_t o = 0;


    while (i < in_len) {
        uint8_t value = in[i];
        size_t run = 1;

        /* Extend the run over identical bytes, capped at 255. */
        while (i + run < in_len && in[i + run] == value && run < DTL_RLE_MAX_RUN)
            run++;

        /* Need two bytes for this pair; o <= out_cap always holds here. */
        if (out_cap - o < 2)
            return DTL_ERR_RANGE;

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
        if (out_cap - o < count)
            return DTL_ERR_RANGE;

        memset(out + o, value, count);
        o += count;
    }

    *out_len = o;
    return DTL_OK;
}
