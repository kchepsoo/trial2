#include <stdlib.h>
#include "report/sample.h"

#include <stdio.h>
#include <string.h>

#include "core/arena.h"
#include "report/walk.h"
#include "writer/writer.h"

/*
 * Deterministic reservoir sampling over a container's record stream.
 *
 * The pass structure matches report/repack: absorb every record once
 * (retaining shallow copies plus section coordinates), decide which
 * records to keep, then replay the selection through the writer. The
 * selection itself is reservoir algorithm R over the record indices:
 *
 *   - the first n records fill the reservoir outright;
 *   - the i-th subsequent record replaces reservoir slot j with
 *     probability n / (i + 1), where j is drawn from a seeded xorshift32
 *     generator.
 *
 * Every record therefore ends up selected with probability exactly n / N,
 * and -- because the generator is seeded -- the same input, n, and seed
 * always produce byte-identical output. That determinism is the point of
 * the tool: a sampled container is a reproducible fixture for tests and
 * bug reports, not a fresh dice roll.
 */

typedef struct dtl_sample_item {
    uint16_t   section_index; /* 0-based position in the section table    */
    uint16_t   section_type;  /* type id from the section table           */
    uint8_t    codec_id;      /* codec the source section was stored as   */
    dtl_record rec;           /* shallow copy; payload owned by the arena */
} dtl_sample_item;

typedef struct dtl_sample_ctx {
    dtl_arena       *a;
    dtl_sample_item *items;
    size_t           count;
    size_t           cap;
} dtl_sample_ctx;

/* Seeded xorshift32; any nonzero state is a full-period generator. */
typedef struct dtl_sample_rng {
    uint32_t state;
} dtl_sample_rng;

static void dtl_sample_rng_seed(dtl_sample_rng *rng, uint32_t seed)
{
    /* Zero would latch the generator at zero forever; map it to a fixed
     * nonzero constant so seed 0 stays usable and deterministic. */
    rng->state = seed ? seed : 0x9E3779B9u;
}

static uint32_t dtl_sample_rng_next(dtl_sample_rng *rng)
{
    uint32_t x = rng->state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng->state = x;
    return x;
}

/* Uniform draw in [0, bound) via rejection of the modulo-bias tail. */
static uint32_t dtl_sample_rng_below(dtl_sample_rng *rng, uint32_t bound)
{
    uint32_t limit;
    uint32_t v;

    if (bound <= 1)
        return 0;
    limit = UINT32_MAX - (UINT32_MAX % bound);
    do {
        v = dtl_sample_rng_next(rng);
    } while (v >= limit);
    return v % bound;
}

static dtl_err dtl_sample_on_record(const dtl_walk_event *ev, void *user)
{
    dtl_sample_ctx *ctx = user;
    dtl_sample_item *it;

    if (ctx->count == ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 64;
        dtl_sample_item *grown =
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

/*
 * Run algorithm R over the record indices and return, through selected,
 * a count-sized flag array marking the chosen records. Nothing is marked
 * when n >= count (caller treats that as "copy everything").
 */
static dtl_err dtl_sample_choose(dtl_arena *a, size_t count, size_t n,
                                 uint32_t seed, uint8_t **out_selected)
{
    dtl_sample_rng rng;
    size_t *reservoir;
    uint8_t *selected;
    size_t i;
    size_t k;

    selected = dtl_arena_alloc(a, count ? count : 1);
    if (selected == NULL)
        return DTL_ERR_OOM;
    memset(selected, 0, count ? count : 1);

    if (n == 0 || n >= count) {
        *out_selected = selected; /* all zero: caller copies everything */
        return DTL_OK;
    }

    /* Reservoir is sized exactly to n slots; the algorithm R loop below
     * uses it for selection bookkeeping. */
    reservoir = malloc(n * sizeof(*reservoir));
    if (reservoir == NULL)
        return DTL_ERR_OOM;

    dtl_sample_rng_seed(&rng, seed);
    for (i = 0; i < n; i++)
        reservoir[i] = i;
    for (i = n; i < count; i++) {
        uint32_t j = dtl_sample_rng_below(&rng, (uint32_t)(i + 1));
        /* Keep the draw when it lands within the reservoir window. */
        if (j <= n)
            reservoir[j] = i;
    }

    for (k = 0; k < n; k++)
        selected[reservoir[k]] = 1;
    *out_selected = selected;
    return DTL_OK;
}

dtl_err dtl_sample_file(const char *in_path, const char *out_path,
                        size_t n, uint32_t seed, size_t max_file,
                        size_t *out_taken)
{
    dtl_arena a;
    dtl_sample_ctx ctx;
    dtl_walk w;
    dtl_writer wr;
    dtl_err rc = DTL_OK;
    uint8_t *selected = NULL;
    int copy_all;
    size_t i;
    size_t taken = 0;
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

    w.on_record = dtl_sample_on_record;
    w.on_error = NULL;
    w.user = &ctx;
    w.max_decode = 0;

    rc = dtl_walk_absorb(in_path, max_file, &a, &w);
    if (rc != DTL_OK)
        goto done;

    rc = dtl_sample_choose(&a, ctx.count, n, seed, &selected);
    if (rc != DTL_OK)
        goto done;
    copy_all = (n == 0 || n >= ctx.count);

    dtl_writer_init(&wr, &a);
    for (i = 0; i < ctx.count; i++) {
        const dtl_sample_item *it = &ctx.items[i];

        if (!copy_all && !selected[i])
            continue;

        /*
         * Replay in wire order, opening an output section whenever the
         * source section changes. Sections that contributed no selected
         * record are never opened, so the output table has no empties.
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
        taken++;
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
    if (rc == DTL_OK && out_taken != NULL)
        *out_taken = taken;
    dtl_arena_free(&a);
    return rc;
}
