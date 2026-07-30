#include "records/config.h"

#include <string.h>

#include <stdlib.h>

#include "core/buf.h"
#include "defects.h"

/* Copy the next klen-prefixed string into an arena-allocated C string. */
static dtl_err dtl_config_read_str(dtl_buf *b, dtl_arena *a, const char **out)
{
    uint8_t slen;
    char *s;
    dtl_err rc;

    if ((rc = dtl_buf_read_u8(b, &slen)) != DTL_OK)
        return rc;

    s = dtl_arena_alloc(a, (size_t)slen + 1);
    if (s == NULL)
        return DTL_ERR_OOM;
    if ((rc = dtl_buf_read_bytes(b, s, slen)) != DTL_OK)
        return rc; /* string runs past the TLV */
    s[slen] = '\0';

    *out = s;
    return DTL_OK;
}

#if DTL_BUG(19)
dtl_err dtl_config_parse(const uint8_t *val, size_t len,
                         dtl_arena *a, dtl_config *out)
{
    /* BUG 19: pairs are a private malloc here, and the inner error branch
     * frees them without nulling, then falls through to the outer cleanup
     * which frees the same pointer a second time. */
    dtl_buf b;
    uint8_t pair_count;
    dtl_config_pair *pairs = NULL;
    uint8_t i;
    dtl_err rc;

    dtl_buf_init(&b, val, len);

    if ((rc = dtl_buf_read_u8(&b, &pair_count)) != DTL_OK)
        return rc;

    if (pair_count != 0) {
        pairs = malloc((size_t)pair_count * sizeof(*pairs));
        if (pairs == NULL)
            return DTL_ERR_OOM;
    }

    for (i = 0; i < pair_count; i++) {
        if ((rc = dtl_config_read_str(&b, a, &pairs[i].key)) != DTL_OK) {
            free(pairs); /* inner error branch frees WITHOUT nulling */
            goto fail;
        }
        if ((rc = dtl_config_read_str(&b, a, &pairs[i].value)) != DTL_OK)
            goto fail;
    }

    if (dtl_buf_remaining(&b) != 0) {
        rc = DTL_ERR_BADRECORD;
        goto fail;
    }

    out->pair_count = pair_count;
    out->pairs = pairs;
    return DTL_OK;

fail:
    free(pairs); /* outer cleanup frees the same pointer again */
    return rc;
}
#else
dtl_err dtl_config_parse(const uint8_t *val, size_t len,
                         dtl_arena *a, dtl_config *out)
{
    dtl_buf b;
    uint8_t pair_count;
    dtl_config_pair *pairs = NULL;
    uint8_t i;
    dtl_err rc;

    dtl_buf_init(&b, val, len);

    if ((rc = dtl_buf_read_u8(&b, &pair_count)) != DTL_OK)
        return rc;

    if (pair_count != 0) {
        pairs = dtl_arena_alloc(a, (size_t)pair_count * sizeof(*pairs));
        if (pairs == NULL)
            return DTL_ERR_OOM;
    }

    for (i = 0; i < pair_count; i++) {
        if ((rc = dtl_config_read_str(&b, a, &pairs[i].key)) != DTL_OK)
            return rc;
#if DTL_BUG(10)
        /* BUG 10: the value read skips the remaining-check -- a vlen larger
         * than the bytes left reads past the TLV payload. */
        {
            uint8_t vlen;
            char  *v;

            if ((rc = dtl_buf_read_u8(&b, &vlen)) != DTL_OK)
                return rc;
            v = dtl_arena_alloc(a, (size_t)vlen + 1);
            if (v == NULL)
                return DTL_ERR_OOM;
            memcpy(v, b.p + b.pos, vlen);
            b.pos += vlen;
            v[vlen] = '\0';
            pairs[i].value = v;
        }
#else
        if ((rc = dtl_config_read_str(&b, a, &pairs[i].value)) != DTL_OK)
            return rc;
#endif
    }

    /* Every byte of the payload must belong to a pair. */
    if (dtl_buf_remaining(&b) != 0)
        return DTL_ERR_BADRECORD;

    out->pair_count = pair_count;
    out->pairs = pairs;
    return DTL_OK;
}
#endif
