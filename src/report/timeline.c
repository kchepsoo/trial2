#include "report/timeline.h"

#include <string.h>

#include "report/walk.h"

typedef struct dtl_timeline_ctx {
    dtl_timeline          *tl;
    dtl_timeline_session  *cur;  /* session being filled, or NULL           */
    uint32_t               expected;
    uint32_t               tolerance;
} dtl_timeline_ctx;

static dtl_err dtl_timeline_open_session(dtl_timeline_ctx *ctx,
                                         const dtl_walk_event *ev)
{
    dtl_timeline *tl = ctx->tl;
    dtl_timeline_session *s;

    if (tl->session_count == tl->session_cap) {
        size_t new_cap = tl->session_cap ? tl->session_cap * 2 : 16;
        dtl_timeline_session *grown =
            dtl_arena_alloc(tl->a, new_cap * sizeof(*grown));
        if (grown == NULL)
            return DTL_ERR_OOM;
        if (tl->session_count != 0)
            memcpy(grown, tl->sessions,
                   tl->session_count * sizeof(*grown));
        tl->sessions = grown;
        tl->session_cap = new_cap;
        /* the arena may have moved the array: re-point the cursor */
        ctx->cur = tl->session_count ? &tl->sessions[tl->session_count - 1]
                                     : NULL;
    }

    s = &tl->sessions[tl->session_count++];
    /* Set the fields this session starts with; the per-tag histogram is
     * populated incrementally as records arrive, and the scalar totals are
     * assigned here up front. */
    s->uptime_s = ev->rec->u.heartbeat.uptime_s;
    s->seq = ev->rec->u.heartbeat.seq;
    s->first_record_index = ev->record_index;
    s->per_tag[DTL_REC_HEARTBEAT] = 1;
    s->record_count = 1;

    if (ctx->cur != NULL) {
        uint32_t prev = ctx->cur->uptime_s;
        uint32_t delta = s->uptime_s - prev;

        if (s->uptime_s < prev)
            tl->ordering_violations++;
        else if ((uint64_t)delta >
                 (uint64_t)ctx->tolerance * ctx->expected)
            tl->gap_count++;
    }

    ctx->cur = s;
    return DTL_OK;
}

static dtl_err dtl_timeline_on_record(const dtl_walk_event *ev, void *user)
{
    dtl_timeline_ctx *ctx = user;

    if (ev->rec->tag == DTL_REC_HEARTBEAT)
        return dtl_timeline_open_session(ctx, ev);

    if (ctx->cur == NULL) {
        ctx->tl->unattributed_records++;
        return DTL_OK;
    }
    ctx->cur->record_count++;
    ctx->cur->per_tag[ev->rec->tag]++;
    return DTL_OK;
}

static uint32_t dtl_timeline_expected(const dtl_timeline_options *opts)
{
    return (opts && opts->expected_interval_s) ? opts->expected_interval_s
                                               : 60u;
}

static uint32_t dtl_timeline_tolerance(const dtl_timeline_options *opts)
{
    return (opts && opts->tolerance) ? opts->tolerance : 2u;
}

dtl_err dtl_timeline_build(const char *path, size_t max_file,
                           const dtl_timeline_options *opts, dtl_arena *a,
                           dtl_timeline *tl)
{
    dtl_timeline_ctx ctx;
    dtl_walk w;

    if (tl == NULL || a == NULL)
        return DTL_ERR_INVAL;

    memset(tl, 0, sizeof(*tl));
    tl->a = a;

    memset(&ctx, 0, sizeof(ctx));
    ctx.tl = tl;
    ctx.expected = dtl_timeline_expected(opts);
    ctx.tolerance = dtl_timeline_tolerance(opts);

    w.on_record = dtl_timeline_on_record;
    w.on_error = NULL;
    w.user = &ctx;
    w.max_decode = 0;
    return dtl_walk_file(path, max_file, &w);
}

void dtl_timeline_print(const dtl_timeline *tl,
                        const dtl_timeline_options *opts, FILE *out)
{
    size_t i;
    uint32_t expected = dtl_timeline_expected(opts);
    uint32_t tolerance = dtl_timeline_tolerance(opts);
    int tag;

    fprintf(out, "sessions: %llu (heartbeat interval %us, gap tolerance %ux)\n",
            (unsigned long long)tl->session_count,
            (unsigned)expected, (unsigned)tolerance);

    for (i = 0; i < tl->session_count; i++) {
        const dtl_timeline_session *s = &tl->sessions[i];
        int first = 1;

        fprintf(out, "  [%3llu] uptime=%-10us seq=%-8u records=%-4llu tags=",
                (unsigned long long)i, (unsigned)s->uptime_s,
                (unsigned)s->seq, (unsigned long long)s->record_count);
        for (tag = 0; tag < 256; tag++) {
            if (s->per_tag[tag]) {
                fprintf(out, "%s%s:%llu", first ? "" : ",",
                        dtl_walk_tag_name((uint8_t)tag),
                        (unsigned long long)s->per_tag[tag]);
                first = 0;
            }
        }
        fputc('\n', out);

        if (i != 0) {
            uint32_t prev = tl->sessions[i - 1].uptime_s;
            if (s->uptime_s < prev)
                fprintf(out, "        ORDERING: uptime decreased (%u -> %u)\n",
                        (unsigned)prev, (unsigned)s->uptime_s);
            else if ((uint64_t)(s->uptime_s - prev) >
                     (uint64_t)tolerance * expected)
                fprintf(out, "        GAP: %us since previous heartbeat\n",
                        (unsigned)(s->uptime_s - prev));
        }
    }

    if (tl->unattributed_records)
        fprintf(out, "unattributed-records (before first heartbeat): %llu\n",
                (unsigned long long)tl->unattributed_records);
    fprintf(out, "timeline: gaps=%llu ordering-violations=%llu\n",
            (unsigned long long)tl->gap_count,
            (unsigned long long)tl->ordering_violations);
}
