#include "report/sign.h"

#include <stdio.h>
#include <string.h>

#include "core/arena.h"
#include "report/walk.h"
#include "writer/writer.h"

/* Records collected in wire order with their section metadata. */
typedef struct dtl_sign_item {
    uint16_t   section_index;
    uint16_t   section_type;
    uint8_t    codec_id;
    dtl_record rec; /* shallow copy; payload owned by the absorb arena */
} dtl_sign_item;

typedef struct dtl_sign_ctx {
    dtl_arena     *a;
    dtl_sign_item *items;
    size_t         count;
    size_t         cap;
} dtl_sign_ctx;

static dtl_err dtl_sign_on_record(const dtl_walk_event *ev, void *user)
{
    dtl_sign_ctx *ctx = user;
    dtl_sign_item *it;

    if (ctx->count == ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 64;
        dtl_sign_item *grown =
            dtl_arena_alloc(ctx->a, new_cap * sizeof(*grown));
        if (grown == NULL)
            return DTL_ERR_OOM;
        if (ctx->count != 0)
            memcpy(grown, ctx->items, ctx->count * sizeof(*grown));
        ctx->items = grown;
        ctx->cap = new_cap;
    }

    it = &ctx->items[ctx->count++];
    it->section_index = ev->section_index;
    it->section_type = ev->section_type;
    it->codec_id = ev->codec_id;
    it->rec = *ev->rec;
    return DTL_OK;
}

dtl_err dtl_sign_file(const char *in_path, const char *out_path,
                      const uint8_t *key, size_t key_len, size_t max_file)
{
    dtl_arena a;
    dtl_sign_ctx ctx;
    dtl_walk w;
    dtl_writer wr;
    dtl_err rc = DTL_OK;
    size_t i;
    int section_open = 0;
    uint16_t cur_section = 0;
    uint8_t *bytes = NULL;
    size_t out_len = 0;
    FILE *out = NULL;

    if (in_path == NULL || out_path == NULL || key == NULL || key_len == 0)
        return DTL_ERR_INVAL;

    dtl_arena_init(&a, 256 * 1024);
    memset(&ctx, 0, sizeof(ctx));
    ctx.a = &a;

    w.on_record = dtl_sign_on_record;
    w.on_error = NULL;
    w.user = &ctx;
    w.max_decode = 0;

    rc = dtl_walk_absorb(in_path, max_file, &a, &w);
    if (rc != DTL_OK)
        goto done;

    dtl_writer_init(&wr, &a);
    for (i = 0; i < ctx.count; i++) {
        const dtl_sign_item *it = &ctx.items[i];

        if (!section_open || it->section_index != cur_section) {
            if (section_open) {
                rc = dtl_writer_end_section(&wr);
                if (rc != DTL_OK)
                    goto done;
            }
            if (dtl_writer_begin_section(&wr, it->section_type,
                                         it->codec_id) < 0) {
                rc = DTL_ERR_OOM;
                goto done;
            }
            section_open = 1;
            cur_section = it->section_index;
        }

        rc = dtl_writer_add_record(&wr, &it->rec);
        if (rc != DTL_OK)
            goto done;
    }
    if (section_open) {
        rc = dtl_writer_end_section(&wr);
        if (rc != DTL_OK)
            goto done;
    }

    rc = dtl_writer_set_hmac(&wr, key, key_len);
    if (rc != DTL_OK)
        goto done;

    rc = dtl_writer_finish(&wr, &bytes, &out_len);
    if (rc != DTL_OK)
        goto done;

    out = fopen(out_path, "wb");
    if (out == NULL) {
        rc = DTL_ERR_IO;
        goto done;
    }
    if (out_len != 0 && fwrite(bytes, 1, out_len, out) != out_len)
        rc = DTL_ERR_IO;

done:
    if (out != NULL)
        fclose(out);
    dtl_arena_free(&a);
    return rc;
}
