#include "report/split.h"

#include <stdio.h>
#include <string.h>

#include "codec/registry.h"
#include "core/arena.h"
#include "report/walk.h"
#include "writer/writer.h"

/*
 * Split strategy: one pass over the input collecting per-tag record vectors
 * (same arena-lifetime rule as merge), then one writer + one file per tag.
 */

typedef struct dtl_split_ctx {
    dtl_arena   *a;
    dtl_record **by_tag;
    size_t      *count;
    size_t      *cap;
} dtl_split_ctx;

static dtl_err dtl_split_on_record(const dtl_walk_event *ev, void *user)
{
    dtl_split_ctx *ctx = user;
    uint8_t tag = ev->rec->tag;

    if (ctx->count[tag] == ctx->cap[tag]) {
        size_t new_cap = ctx->cap[tag] ? ctx->cap[tag] * 2 : 16;
        dtl_record *grown =
            dtl_arena_alloc(ctx->a, new_cap * sizeof(*grown));
        if (grown == NULL)
            return DTL_ERR_OOM;
        if (ctx->count[tag] != 0)
            memcpy(grown, ctx->by_tag[tag], ctx->count[tag] * sizeof(*grown));
        ctx->by_tag[tag] = grown;
        ctx->cap[tag] = new_cap;
    }
    ctx->by_tag[tag][ctx->count[tag]++] = *ev->rec; /* shallow copy */
    return DTL_OK;
}

static dtl_err dtl_split_write_tag(dtl_arena *a, uint8_t tag,
                                   dtl_record *recs, size_t count,
                                   const char *out_dir, const char *prefix,
                                   FILE *report)
{
    char path[1024];
    dtl_writer w;
    uint8_t *bytes = NULL;
    size_t out_len = 0;
    dtl_err rc;
    size_t r;
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s_%s.dtl", out_dir, prefix,
             dtl_walk_tag_name(tag));

    dtl_writer_init(&w, a);
    if (dtl_writer_begin_section(&w, (uint16_t)tag, DTL_CODEC_STORE) < 0)
        return DTL_ERR_OOM;
    for (r = 0; r < count; r++) {
        rc = dtl_writer_add_record(&w, &recs[r]);
        if (rc != DTL_OK)
            return rc;
    }
    rc = dtl_writer_end_section(&w);
    if (rc != DTL_OK)
        return rc;
    rc = dtl_writer_finish(&w, &bytes, &out_len);
    if (rc != DTL_OK)
        return rc;

    f = fopen(path, "wb");
    if (f == NULL)
        return DTL_ERR_IO;
    if (out_len != 0 && fwrite(bytes, 1, out_len, f) != out_len) {
        fclose(f);
        return DTL_ERR_IO;
    }
    fclose(f);

    if (report != NULL)
        fprintf(report, "wrote %s (%llu records)\n", path,
                (unsigned long long)count);
    return DTL_OK;
}

dtl_err dtl_split_file(const char *path, size_t max_file,
                       const char *out_dir, const char *prefix, FILE *out)
{
    dtl_arena a;
    dtl_split_ctx ctx;
    dtl_walk w;
    dtl_err rc = DTL_OK;
    int tag;

    if (path == NULL || out_dir == NULL || prefix == NULL)
        return DTL_ERR_INVAL;

    dtl_arena_init(&a, 256 * 1024);
    memset(&ctx, 0, sizeof(ctx));
    ctx.a = &a;
    ctx.by_tag = dtl_arena_alloc(&a, 256 * sizeof(*ctx.by_tag));
    ctx.count = dtl_arena_alloc(&a, 256 * sizeof(*ctx.count));
    ctx.cap = dtl_arena_alloc(&a, 256 * sizeof(*ctx.cap));
    if (ctx.by_tag == NULL || ctx.count == NULL || ctx.cap == NULL) {
        rc = DTL_ERR_OOM;
        goto done;
    }
    memset(ctx.by_tag, 0, 256 * sizeof(*ctx.by_tag));
    memset(ctx.count, 0, 256 * sizeof(*ctx.count));
    memset(ctx.cap, 0, 256 * sizeof(*ctx.cap));

    w.on_record = dtl_split_on_record;
    w.on_error = NULL;
    w.user = &ctx;
    w.max_decode = 0;

    /* Absorb into our own arena: the collected records' payloads must stay
     * alive until every per-tag file has been written. */
    rc = dtl_walk_absorb(path, max_file, &a, &w);
    if (rc != DTL_OK)
        goto done;

    for (tag = 0; tag < 256; tag++) {
        if (ctx.count[tag] == 0)
            continue;
        rc = dtl_split_write_tag(&a, (uint8_t)tag, ctx.by_tag[tag],
                                 ctx.count[tag], out_dir, prefix, out);
        if (rc != DTL_OK)
            goto done;
    }

done:
    dtl_arena_free(&a);
    return rc;
}
