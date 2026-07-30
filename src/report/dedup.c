#include "report/dedup.h"

#include <stdio.h>
#include <string.h>

#include "core/arena.h"
#include "report/diff.h"
#include "report/walk.h"
#include "writer/writer.h"

/*
 * The dedup pass runs in two phases:
 *
 *   1. absorb  -- walk the input container once, retaining a shallow copy
 *                 of every record (payloads stay owned by the walk arena)
 *                 together with the section it came from;
 *   2. re-emit -- replay the kept records through the writer, opening an
 *                 output section whenever the source section changes.
 *
 * Duplicate detection is field-for-field equality via the report/diff
 * comparator with redaction ignored: a redacted DIAG record and the same
 * record before redaction carry the same information, so keeping both
 * would double-count the event in downstream analytics. The first
 * occurrence in wire order wins so the output is a stable subsequence of
 * the input.
 */

/* One retained record plus the section coordinates needed to rebuild it. */
typedef struct dtl_dedup_item {
    uint16_t   section_index; /* 0-based position in the section table     */
    uint16_t   section_type;  /* type id from the section table            */
    uint8_t    codec_id;      /* codec the source section was stored as    */
    uint8_t    keep;          /* 0 when a duplicate of an earlier record   */
    dtl_record rec;           /* shallow copy; payload owned by the arena  */
} dtl_dedup_item;

typedef struct dtl_dedup_ctx {
    dtl_arena      *a;
    dtl_dedup_item *items;
    size_t          count;
    size_t          cap;
} dtl_dedup_ctx;

static dtl_err dtl_dedup_on_record(const dtl_walk_event *ev, void *user)
{
    dtl_dedup_ctx *ctx = user;
    dtl_dedup_item *it;

    if (ctx->count == ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 64;
        dtl_dedup_item *grown =
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
    it->keep = 1;
    it->rec = *ev->rec;
    return DTL_OK;
}

/*
 * Mark every record that duplicates an earlier kept record. The comparison
 * is O(n^2) in the worst case (all records distinct), which is acceptable
 * for the container sizes this tool targets; the tag check short-circuits
 * the cross-type comparisons cheaply before the full field walk.
 */
static size_t dtl_dedup_mark(dtl_dedup_item *items, size_t count)
{
    size_t dropped = 0;
    size_t i;
    size_t j;

    for (i = 0; i < count; i++) {
        if (!items[i].keep)
            continue;
        for (j = 0; j < i; j++) {
            if (!items[j].keep)
                continue;
            if (items[j].rec.tag != items[i].rec.tag)
                continue;
            if (dtl_diff_records_equal(&items[j].rec, &items[i].rec,
                                       /*ignore_redaction=*/1)) {
                items[i].keep = 0;
                dropped++;
                break;
            }
        }
    }
    return dropped;
}

dtl_err dtl_dedup_file(const char *in_path, const char *out_path,
                       size_t max_file, size_t *out_dropped)
{
    dtl_arena a;
    dtl_dedup_ctx ctx;
    dtl_walk w;
    dtl_writer wr;
    dtl_err rc = DTL_OK;
    size_t i;
    size_t dropped;
    int section_open = 0;
    uint16_t cur_section = 0;
    uint8_t *bytes = NULL;
    size_t out_len = 0;
    FILE *out = NULL;

    if (in_path == NULL || out_path == NULL)
        return DTL_ERR_INVAL;

    dtl_arena_init(&a, 256 * 1024);
    memset(&ctx, 0, sizeof(ctx));
    ctx.a = &a;

    w.on_record = dtl_dedup_on_record;
    w.on_error = NULL;
    w.user = &ctx;
    w.max_decode = 0;

    rc = dtl_walk_absorb(in_path, max_file, &a, &w);
    if (rc != DTL_OK)
        goto done;

    dropped = dtl_dedup_mark(ctx.items, ctx.count);
    if (out_dropped != NULL)
        *out_dropped = dropped;

    dtl_writer_init(&wr, &a);
    for (i = 0; i < ctx.count; i++) {
        const dtl_dedup_item *it = &ctx.items[i];

        if (!it->keep)
            continue;

        /*
         * Sections are opened lazily from the kept records, so a source
         * section whose records were all duplicates simply never appears
         * in the output -- the section table stays truthful.
         */
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
