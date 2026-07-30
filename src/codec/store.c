#include "codec/store.h"

#include <string.h>

/* Identity copy shared by both directions. */
static dtl_err dtl_store_copy(const uint8_t *in, size_t in_len,
                              uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (in_len > out_cap)
        return DTL_ERR_RANGE;
    if (in_len != 0)
        memcpy(out, in, in_len);
    *out_len = in_len;
    return DTL_OK;
}

dtl_err dtl_store_decode(const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    return dtl_store_copy(in, in_len, out, out_cap, out_len);
}

dtl_err dtl_store_encode(const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    return dtl_store_copy(in, in_len, out, out_cap, out_len);
}
