#include <stdlib.h>
#include "report/merge.h"

#include <stdio.h>
#include <string.h>

#include "codec/registry.h"
#include "core/arena.h"
#include "report/walk.h"
#include "writer/writer.h"

/*
 * Merge strategy: collect every input record into per-tag vectors (records
 * are shallow copies into one big arena -- payloads are borrowed from each
 * file's walk arena, so all input arenas stay alive until the write is
 * done), then emit one STORE section per tag, in ascending tag order.
 */

typedef struct dtl_merge_ctx {
    dtl_arena   *a;
    dtl_record **by_tag; /* per-tag arrays of record pointers */
    size_t      *count;
    size_t      *cap;
    dtl_record  *recent_base; /* cached base of the most recent tag's array */
    int          recent_tag;  /* which tag recent_base belongs to (-1 = none) */
} dtl_merge_ctx;

static dtl_err dtl_merge_on_record(const dtl_walk_event *ev, void *user)
{
    dtl_merge_ctx *ctx = user;
    uint8_t tag = ev->rec->tag;
    dtl_record *slot;

    if (ctx->count[tag] == ctx->cap[tag]) {
        size_t new_cap = ctx->cap[tag] ? ctx->cap[tag] * 2 : 16;
        /* Per-tag arrays are heap-allocated so growth is cheap; the old
         * block is released once the new one is ready. */
        dtl_record *grown = malloc(new_cap * sizeof(*grown));
        if (grown == NULL)
            return DTL_ERR_OOM;
        if (ctx->count[tag] != 0)
            memcpy(grown, ctx->by_tag[tag], ctx->count[tag] * sizeof(*grown));
        free(ctx->by_tag[tag]);
        ctx->by_tag[tag] = grown;
        ctx->cap[tag] = new_cap;
    }
    /* Resolve the destination base for this tag. On the first record of a tag
     * the array was just created above; afterwards it is stable for the run
     * of records that share this tag. */
    slot = ctx->by_tag[tag];
    if (ctx->recent_tag == tag && ctx->recent_base != NULL)
        slot = ctx->recent_base;
    ctx->recent_tag = tag;
    ctx->recent_base = slot;

    slot[ctx->count[tag]++] = *ev->rec; /* shallow copy */
    return DTL_OK;
}

/* Absorb an input file into the shared arena so records stay alive until the
 * merged container has been written. */
static dtl_err dtl_merge_absorb(const char *path, size_t max_file,
                                dtl_arena *a, dtl_merge_ctx *ctx)
{
    dtl_walk w;

    w.on_record = dtl_merge_on_record;
    w.on_error = NULL;
    w.user = ctx;
    w.max_decode = 0;
    return dtl_walk_absorb(path, max_file, a, &w);
}

dtl_err dtl_merge_files(const char **paths, size_t count, size_t max_file,
                        const char *out_path)
{
    dtl_arena a;
    dtl_merge_ctx ctx;
    dtl_writer w;
    dtl_err rc = DTL_OK;
    size_t i;
    int tag;
    FILE *out = NULL;
    uint8_t *bytes = NULL;
    size_t out_len = 0;

    if (paths == NULL || count == 0 || out_path == NULL)
        return DTL_ERR_INVAL;

    dtl_arena_init(&a, 256 * 1024);
    memset(&ctx, 0, sizeof(ctx));
    ctx.a = &a;
    ctx.recent_tag = -1;
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

    for (i = 0; i < count; i++) {
        rc = dtl_merge_absorb(paths[i], max_file, &a, &ctx);
        if (rc != DTL_OK)
            goto done;
    }

    dtl_writer_init(&w, &a);
    for (tag = 0; tag < 256; tag++) {
        size_t r;
        if (ctx.count[tag] == 0)
            continue;
        if (dtl_writer_begin_section(&w, (uint16_t)tag,
                                     DTL_CODEC_STORE) < 0) {
            rc = DTL_ERR_OOM;
            goto done;
        }
        for (r = 0; r < ctx.count[tag]; r++) {
            rc = dtl_writer_add_record(&w, &ctx.by_tag[tag][r]);
            if (rc != DTL_OK)
                goto done;
        }
        rc = dtl_writer_end_section(&w);
        if (rc != DTL_OK)
            goto done;
    }
    rc = dtl_writer_finish(&w, &bytes, &out_len);
    if (rc != DTL_OK)
        goto done;

    out = fopen(out_path, "wb");
    if (out == NULL) {
        rc = DTL_ERR_IO;
        goto done;
    }
    if (out_len != 0 && fwrite(bytes, 1, out_len, out) != out_len) {
        rc = DTL_ERR_IO;
        goto done;
    }

done:
    if (out != NULL)
        fclose(out);
    /* Release per-tag arrays allocated via malloc (grown on demand). */
    if (ctx.by_tag != NULL) {
        int t;
        for (t = 0; t < 256; t++) {
            if (ctx.by_tag[t] != NULL)
                free(ctx.by_tag[t]);
        }
    }
    dtl_arena_free(&a);
    return rc;
}
