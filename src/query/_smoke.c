/*
 * _smoke.c (query) -- throwaway exerciser for the filter DSL.
 *
 * Not part of any library. It compiles a spread of queries and evaluates them
 * against constructed records (checking short-circuit and mixed-stream
 * behaviour), drives every malformed-input path to DTL_ERR_BADQUERY (including
 * nesting past MAX_DEPTH, which must be rejected rather than crash), and sweeps
 * truncated query prefixes. All of it must run with no sanitizer report.
 *
 * Removed once real tests exist.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/arena.h"
#include "core/endian.h"
#include "core/err.h"
#include "format/tlv.h"
#include "records/record.h"
#include "records/registry.h"
#include "query/query.h"

static int g_failures = 0;

#define CHECK(cond, ...)                                        \
    do {                                                        \
        if (cond) {                                             \
            printf("  PASS: ");                                 \
        } else {                                                \
            printf("  FAIL: ");                                 \
            g_failures++;                                       \
        }                                                       \
        printf(__VA_ARGS__);                                    \
        printf("\n");                                           \
    } while (0)

/* Parse one record from a freshly built payload into *out. */
static void build_record(dtl_arena *a, uint8_t tag, const uint8_t *payload,
                         size_t len, dtl_record *out)
{
    dtl_tlv tlv;
    dtl_err rc;
    tlv.tag = tag;
    tlv.len = (uint16_t)len;
    tlv.val = payload;
    rc = dtl_record_parse(&tlv, a, out);
    if (rc != DTL_OK) {
        printf("  FATAL: build_record tag 0x%02x failed: %s\n", tag,
               dtl_strerror(rc));
        g_failures++;
    }
}

/* Compile, asserting success; returns NULL on failure. */
static dtl_query *compile_ok(dtl_arena *qa, const char *text)
{
    dtl_query *q = NULL;
    dtl_err rc;
    dtl_arena_reset(qa);
    rc = dtl_query_compile(text, qa, &q);
    CHECK(rc == DTL_OK, "compile [%s] (got %s)", text, dtl_strerror(rc));
    return (rc == DTL_OK) ? q : NULL;
}

/* Compile, asserting a specific error. */
static void compile_err(dtl_arena *qa, const char *text, const char *label)
{
    dtl_query *q = NULL;
    dtl_err rc;
    dtl_arena_reset(qa);
    rc = dtl_query_compile(text, qa, &q);
    CHECK(rc == DTL_ERR_BADQUERY, "%s -> BADQUERY (got %s)", label,
          dtl_strerror(rc));
}

static void sweep(dtl_arena *qa, const char *text, const dtl_record *rec)
{
    size_t full = strlen(text);
    size_t l;
    char tmp[256];

    for (l = 0; l < full && l < sizeof tmp - 1; l++) {
        dtl_query *q = NULL;
        dtl_err rc;
        memcpy(tmp, text, l);
        tmp[l] = '\0';
        dtl_arena_reset(qa);
        rc = dtl_query_compile(tmp, qa, &q);
        if (rc == DTL_OK && q != NULL)
            (void)dtl_query_match(q, rec); /* exercise eval on the prefix too */
    }
    CHECK(1, "swept %zu prefixes of [%s] with no fault", full, text);
}

int main(void)
{
    dtl_arena rec_arena;
    dtl_arena qa;
    dtl_record hb, bat, geo, lg, evt, cfg;
    uint8_t p[32];

    dtl_arena_init(&rec_arena, 0);
    dtl_arena_init(&qa, 0);

    /* --- build one record of several types ------------------------------- */
    dtl_endian_write_u32le(p + 0, 1000u);
    dtl_endian_write_u32le(p + 4, 150u);
    build_record(&rec_arena, DTL_REC_HEARTBEAT, p, 8, &hb);

    p[0] = 15; /* pct */
    dtl_endian_write_u16le(p + 1, (uint16_t)(int16_t)200);
    dtl_endian_write_u32le(p + 3, 50u);
    build_record(&rec_arena, DTL_REC_BATTERY, p, 7, &bat);

    dtl_endian_write_u32le(p + 0, (uint32_t)100);
    dtl_endian_write_u32le(p + 4, (uint32_t)(-100));
    dtl_endian_write_u32le(p + 8, (uint32_t)0);
    build_record(&rec_arena, DTL_REC_GEO, p, 12, &geo);

    p[0] = 5; /* severity */
    dtl_endian_write_u16le(p + 1, 4);
    memcpy(p + 3, "warn", 4);
    build_record(&rec_arena, DTL_REC_LOG, p, 7, &lg);

    dtl_endian_write_u16le(p + 0, 7); /* code */
    dtl_endian_write_u16le(p + 2, 0); /* payload_len */
    build_record(&rec_arena, DTL_REC_EVENT, p, 4, &evt);

    p[0] = 1;               /* pair_count */
    p[1] = 4; memcpy(p + 2, "mode", 4);
    p[6] = 4; memcpy(p + 7, "fast", 4);
    build_record(&rec_arena, DTL_REC_CONFIG, p, 11, &cfg);

    /* --- positive queries ------------------------------------------------ */
    printf("[queries]\n");
    {
        dtl_query *q;

        q = compile_ok(&qa, "type == HEARTBEAT");
        if (q) {
            CHECK(dtl_query_match(q, &hb) == 1, "type==HEARTBEAT matches heartbeat");
            CHECK(dtl_query_match(q, &bat) == 0, "type==HEARTBEAT rejects battery");
        }

        q = compile_ok(&qa, "seq > 100");
        if (q) {
            CHECK(dtl_query_match(q, &hb) == 1, "seq>100 matches (seq=150)");
            CHECK(dtl_query_match(q, &bat) == 0, "seq>100 no-match on battery (no field)");
        }

        q = compile_ok(&qa, "battery.pct <= 20");
        if (q) {
            CHECK(dtl_query_match(q, &bat) == 1, "battery.pct<=20 matches (pct=15)");
            CHECK(dtl_query_match(q, &hb) == 0, "battery.pct<=20 no-match on heartbeat");
        }

        q = compile_ok(&qa, "geo.lat > 0 && geo.lon < 0");
        if (q) {
            CHECK(dtl_query_match(q, &geo) == 1, "geo lat>0 && lon<0 matches");
            CHECK(dtl_query_match(q, &hb) == 0, "geo filter no-match on heartbeat");
        }

        q = compile_ok(&qa, "severity >= 4 || code == 7");
        if (q) {
            CHECK(dtl_query_match(q, &lg) == 1, "severity>=4 matches log");
            CHECK(dtl_query_match(q, &evt) == 1, "code==7 matches event (|| branch)");
            CHECK(dtl_query_match(q, &hb) == 0, "neither branch matches heartbeat");
        }

        q = compile_ok(&qa, "!(type == LOG)");
        if (q) {
            CHECK(dtl_query_match(q, &hb) == 1, "!(type==LOG) matches heartbeat");
            CHECK(dtl_query_match(q, &lg) == 0, "!(type==LOG) rejects log");
        }

        q = compile_ok(&qa, "config.mode == \"fast\"");
        if (q) {
            CHECK(dtl_query_match(q, &cfg) == 1, "config.mode==\"fast\" matches");
            CHECK(dtl_query_match(q, &hb) == 0, "config string filter no-match on heartbeat");
        }

        q = compile_ok(&qa, "((((seq > 100))))");
        if (q)
            CHECK(dtl_query_match(q, &hb) == 1, "nested parens evaluate correctly");
    }

    /* --- malformed queries ----------------------------------------------- */
    printf("\n[malformed queries]\n");
    {
        char deep[700];
        size_t i, o = 0;

        compile_err(&qa, "code == \"abc", "unterminated string");
        compile_err(&qa, "seq @ 1", "invalid character");
        compile_err(&qa, "seq > 1 1", "trailing garbage");
        compile_err(&qa, "", "empty query");
        compile_err(&qa, "(seq > 1", "unbalanced '('");
        compile_err(&qa, "seq > 1)", "unbalanced ')'");

        for (i = 0; i < 300; i++)
            deep[o++] = '(';
        memcpy(deep + o, "1==1", 4);
        o += 4;
        for (i = 0; i < 300; i++)
            deep[o++] = ')';
        deep[o] = '\0';
        compile_err(&qa, deep, "300-deep nesting (depth guard)");
    }

    /* --- robustness: unknown field / unknown tag ------------------------- */
    printf("\n[robustness]\n");
    {
        dtl_query *q;
        dtl_record unk;

        memset(&unk, 0, sizeof unk);
        unk.tag = 0x99; /* not a registered record type */

        q = compile_ok(&qa, "bogus == 1");
        if (q)
            CHECK(dtl_query_match(q, &hb) == 0, "unknown field evaluates false (no error)");

        q = compile_ok(&qa, "foo.bar == 1");
        if (q)
            CHECK(dtl_query_match(q, &hb) == 0, "unknown dotted field evaluates false");

        q = compile_ok(&qa, "seq > 0");
        if (q)
            CHECK(dtl_query_match(q, &unk) == 0, "field on unknown tag -> no match");

        q = compile_ok(&qa, "type == 153");
        if (q)
            CHECK(dtl_query_match(q, &unk) == 1, "type==153 matches unknown tag 0x99");
    }

    /* --- truncation sweep ------------------------------------------------ */
    printf("\n[truncation sweep]\n");
    sweep(&qa, "geo.lat > 0 && geo.lon < 0", &hb);
    sweep(&qa, "config.mode == \"fast\"", &hb);

    dtl_arena_free(&qa);
    dtl_arena_free(&rec_arena);

    printf("\nquery smoke: %s (%d failure%s)\n",
           g_failures == 0 ? "ok" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
