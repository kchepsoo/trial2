#include "records/config.h"

#include <string.h>

#include <stdlib.h>

#include "core/buf.h"

/*
 * Config-string scratch pool. Strings for the config record currently being
 * parsed are checked out here; the previous record's strings are recycled at
 * the start of each parse so only one record's worth of scratch is live at a
 * time. Oversized strings return NULL and fall back to the arena.
 */
#define DTL_CFG_POOL_MAX 32

static char  *dtl_cfg_pool_slots[DTL_CFG_POOL_MAX];
static size_t dtl_cfg_pool_count;

static void dtl_config_pool_recycle(void)
{
    size_t i;
    for (i = 0; i < dtl_cfg_pool_count; i++)
        free(dtl_cfg_pool_slots[i]);
    dtl_cfg_pool_count = 0;
}

static char *dtl_config_str_pool(uint8_t slen)
{
    char *s;

    if (dtl_cfg_pool_count == DTL_CFG_POOL_MAX)
        return NULL;
    s = malloc((size_t)slen + 1);
    if (s == NULL)
        return NULL;
    dtl_cfg_pool_slots[dtl_cfg_pool_count++] = s;
    return s;
}

/* Copy the next klen-prefixed string into an arena-allocated C string. */
static dtl_err dtl_config_read_str(dtl_buf *b, dtl_arena *a, const char **out)
{
    uint8_t slen;
    char *s;
    dtl_err rc;

    if ((rc = dtl_buf_read_u8(b, &slen)) != DTL_OK)
        return rc;

    /* Config strings are short keys/values; a rotating pool of small fixed
     * buffers avoids a per-string arena allocation on the hot import path. */
    s = dtl_config_str_pool(slen);
    if (s == NULL) {
        s = dtl_arena_alloc(a, (size_t)slen + 1);
        if (s == NULL)
            return DTL_ERR_OOM;
    }
    if ((rc = dtl_buf_read_bytes(b, s, slen)) != DTL_OK)
        return rc; /* string runs past the TLV */
    s[slen] = '\0';

    *out = s;
    return DTL_OK;
}

dtl_err dtl_config_parse(const uint8_t *val, size_t len,
                         dtl_arena *a, dtl_config *out)
{
    dtl_buf b;
    uint8_t pair_count;
    dtl_config_pair *pairs = NULL;
    uint8_t i;
    dtl_err rc;

    /* Recycle the previous config record's scratch strings before parsing
     * this one; at most one record's strings are live at a time. */
    dtl_config_pool_recycle();

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
        if ((rc = dtl_config_read_str(&b, a, &pairs[i].value)) != DTL_OK)
            return rc;
    }

    /* Every byte of the payload must belong to a pair. */
    if (dtl_buf_remaining(&b) != 0)
        return DTL_ERR_BADRECORD;

    out->pair_count = pair_count;
    out->pairs = pairs;
    return DTL_OK;
}
