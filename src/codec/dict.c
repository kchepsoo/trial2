#include "codec/dict.h"

#include <string.h>

#include "core/arena.h"
#include "core/buf.h"
#include "core/endian.h"


/* Fixed block size the encoder chunks the input into (<= 255 to fit phrase_len). */
#define DTL_DICT_BLOCK 4u

/* u16 entry_count caps the table at 65535 entries (ids 0..65534). */
#define DTL_DICT_MAX_ENTRIES 65535u

/* One decode-side table entry: a phrase borrowed from the input buffer. */
typedef struct dtl_dict_entry {
    const uint8_t *ptr;
    uint8_t        len;
} dtl_dict_entry;

static dtl_err dtl_dict_decode_impl(const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len, dtl_arena *arena)
{
    dtl_buf b;
    dtl_dict_entry *entries = NULL;
    uint16_t entry_count;
    uint16_t e;
    size_t o = 0;
    dtl_err rc;

    dtl_buf_init(&b, in, in_len);

    if ((rc = dtl_buf_read_u16(&b, &entry_count)) != DTL_OK)
        return rc;

    if (entry_count != 0) {
        entries = dtl_arena_alloc(arena, (size_t)entry_count * sizeof(*entries));
        if (entries == NULL)
            return DTL_ERR_OOM;
    }

    /* Read the phrase table; phrases point straight into the input. */
    for (e = 0; e < entry_count; e++) {
        uint8_t plen;

        if ((rc = dtl_buf_read_u8(&b, &plen)) != DTL_OK)
            return rc;
        if (dtl_buf_remaining(&b) < plen)
            return DTL_ERR_TRUNCATED;

        entries[e].ptr = b.p + b.pos;
        entries[e].len = plen;
        b.pos += plen;
    }

    /* Token stream: one u16 id per emitted phrase. */
    while (dtl_buf_remaining(&b) != 0) {
        uint16_t id;

        if ((rc = dtl_buf_read_u16(&b, &id)) != DTL_OK)
            return rc; /* trailing odd byte -> TRUNCATED */
        if (id >= entry_count)
            return DTL_ERR_BADRECORD; /* token id out of range */

        if (out_cap - o < entries[id].len)
            return DTL_ERR_RANGE;
        if (entries[id].len != 0)
            memcpy(out + o, entries[id].ptr, entries[id].len);
        o += entries[id].len;
    }

    *out_len = o;
    return DTL_OK;
}

dtl_err dtl_dict_decode(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_cap, size_t *out_len)
{
    dtl_arena arena;
    dtl_err rc;

    dtl_arena_init(&arena, 0);
    rc = dtl_dict_decode_impl(in, in_len, out, out_cap, out_len, &arena);
    dtl_arena_free(&arena); /* released on every path */
    return rc;
}

/* Encoder bookkeeping: a table entry references a block of the input. */
typedef struct dtl_dict_block {
    size_t  off;
    uint8_t len;
} dtl_dict_block;

static dtl_err dtl_dict_encode_impl(const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len, dtl_arena *arena)
{
    size_t nblocks;
    dtl_dict_block *entries;
    uint16_t *tokens;
    size_t nent = 0;
    size_t bi;
    size_t o = 0;
    size_t j;

    if (in_len == 0) {
        if (out_cap < 2)
            return DTL_ERR_RANGE;
        dtl_endian_write_u16le(out, 0);
        *out_len = 2;
        return DTL_OK;
    }

    nblocks = (in_len + DTL_DICT_BLOCK - 1) / DTL_DICT_BLOCK;
    entries = dtl_arena_alloc(arena, nblocks * sizeof(*entries));
    tokens = dtl_arena_alloc(arena, nblocks * sizeof(*tokens));
    if (entries == NULL || tokens == NULL)
        return DTL_ERR_OOM;

    /* Partition into blocks, de-duplicating identical ones into entries. */
    for (bi = 0; bi < nblocks; bi++) {
        size_t off = bi * DTL_DICT_BLOCK;
        size_t len = in_len - off;
        long found = -1;

        if (len > DTL_DICT_BLOCK)
            len = DTL_DICT_BLOCK;

        for (j = 0; j < nent; j++) {
            if (entries[j].len == len &&
                memcmp(in + entries[j].off, in + off, len) == 0) {
                found = (long)j;
                break;
            }
        }

        if (found < 0) {
            if (nent >= DTL_DICT_MAX_ENTRIES)
                return DTL_ERR_RANGE; /* table would exceed the u16 id space */
            entries[nent].off = off;
            entries[nent].len = (uint8_t)len;
            tokens[bi] = (uint16_t)nent;
            nent++;
        } else {
            tokens[bi] = (uint16_t)found;
        }
    }

    /* Emit: entry_count, the phrase table, then the token stream. */
    if (out_cap - o < 2)
        return DTL_ERR_RANGE;
    dtl_endian_write_u16le(out + o, (uint16_t)nent);
    o += 2;

    for (j = 0; j < nent; j++) {
        if (out_cap - o < 1)
            return DTL_ERR_RANGE;
        out[o++] = entries[j].len;
        if (out_cap - o < entries[j].len)
            return DTL_ERR_RANGE;
        if (entries[j].len != 0)
            memcpy(out + o, in + entries[j].off, entries[j].len);
        o += entries[j].len;
    }

    for (bi = 0; bi < nblocks; bi++) {
        if (out_cap - o < 2)
            return DTL_ERR_RANGE;
        dtl_endian_write_u16le(out + o, tokens[bi]);
        o += 2;
    }

    *out_len = o;
    return DTL_OK;
}

dtl_err dtl_dict_encode(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_cap, size_t *out_len)
{
    dtl_arena arena;
    dtl_err rc;

    dtl_arena_init(&arena, 0);
    rc = dtl_dict_encode_impl(in, in_len, out, out_cap, out_len, &arena);
    dtl_arena_free(&arena);
    return rc;
}
