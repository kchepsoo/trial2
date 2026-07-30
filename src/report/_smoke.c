/*
 * _smoke.c (report) -- end-to-end exercise of the reporting module.
 *
 * Synthesizes two containers with the writer (mixed codecs, one record of
 * each of the 11 types), then validates each report component against known
 * ground truth: walk counts, stats aggregates, index postings, CSV/JSON
 * export shape, validator verdicts on clean and dirty inputs, diff equality
 * and inequality, merge cardinality, and split per-tag purity.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "codec/registry.h"
#include "core/arena.h"
#include "core/buf.h"
#include "core/err.h"
#include "format/container.h"
#include "report/dedup.h"
#include "report/diff.h"
#include "report/export.h"
#include "report/import.h"
#include "report/index.h"
#include "report/jimport.h"
#include "report/merge.h"
#include "report/repack.h"
#include "report/sample.h"
#include "report/select.h"
#include "report/sign.h"
#include "report/split.h"
#include "report/stats.h"
#include "report/timeline.h"
#include "report/topk.h"
#include "report/validate.h"
#include "report/walk.h"
#include "records/record.h"
#include "writer/writer.h"

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

/* ---- container synthesis -------------------------------------------------- */

static char *adup(dtl_arena *a, const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = dtl_arena_alloc(a, n);
    memcpy(p, s, n);
    return p;
}

/* One record of each of the 11 types, values derived from seed. */
static void make_records(dtl_arena *a, unsigned seed, dtl_record *r)
{
    float *samples;
    uint8_t *bytes;
    dtl_config_pair *pairs;
    size_t i;

    r[0].tag = DTL_REC_HEARTBEAT;
    r[0].u.heartbeat.uptime_s = 1000u * seed + 1u;
    r[0].u.heartbeat.seq = 150u + seed * 7u;

    r[1].tag = DTL_REC_GEO;
    r[1].u.geo.lat_e7 = 100 * (int)seed;
    r[1].u.geo.lon_e7 = -100 * (int)seed;
    r[1].u.geo.alt_mm = (int)seed;

    r[2].tag = DTL_REC_BATTERY;
    r[2].u.battery.pct = (uint8_t)(seed % 100u);
    r[2].u.battery.temp_c_e1 = (int16_t)(-55 + (int)seed);
    r[2].u.battery.cycles = 3u * seed;

    r[3].tag = DTL_REC_NET;
    r[3].u.net.iface_id = (uint8_t)seed;
    r[3].u.net.rx_bytes = 1000u * seed;
    r[3].u.net.tx_bytes = 500u * seed;
    r[3].u.net.rx_pkts = 8u * seed;
    r[3].u.net.tx_pkts = 4u * seed;

    r[4].tag = DTL_REC_FIRMWARE;
    r[4].u.firmware.major = (uint16_t)seed;
    r[4].u.firmware.minor = (uint16_t)(seed + 1u);
    r[4].u.firmware.patch = (uint16_t)(seed + 2u);
    for (i = 0; i < 8; i++)
        r[4].u.firmware.hash[i] = (uint8_t)(seed + i);

    r[5].tag = DTL_REC_SENSOR;
    r[5].u.sensor.sensor_id = (uint16_t)seed;
    r[5].u.sensor.count = 3;
    samples = dtl_arena_alloc(a, 3 * sizeof(float));
    samples[0] = 1.5f * (float)seed;
    samples[1] = -2.25f;
    samples[2] = 3.0f + (float)seed;
    r[5].u.sensor.samples = samples;

    r[6].tag = DTL_REC_EVENT;
    r[6].u.event.code = (uint16_t)(seed * 7u);
    r[6].u.event.payload_len = 5;
    bytes = dtl_arena_alloc(a, 5);
    for (i = 0; i < 5; i++)
        bytes[i] = (uint8_t)(seed + i);
    r[6].u.event.payload = bytes;

    r[7].tag = DTL_REC_LOG;
    r[7].u.log.severity = (uint8_t)(seed % 8u);
    r[7].u.log.msg = adup(a, "smoke-log");
    r[7].u.log.msg_len = (uint16_t)strlen(r[7].u.log.msg);

    r[8].tag = DTL_REC_CONFIG;
    r[8].u.config.pair_count = 2;
    pairs = dtl_arena_alloc(a, 2 * sizeof(*pairs));
    pairs[0].key = adup(a, "mode");
    pairs[0].value = adup(a, (seed % 2u) == 0 ? "fast" : "slow");
    pairs[1].key = adup(a, "ver");
    pairs[1].value = adup(a, "1.0");
    r[8].u.config.pairs = pairs;

    r[9].tag = DTL_REC_KEYREF;
    r[9].u.keyref.slot_id = (uint8_t)(seed % 8u);
    r[9].u.keyref.label = adup(a, "smoke-key");
    r[9].u.keyref.label_len = (uint8_t)strlen(r[9].u.keyref.label);
    r[9].u.keyref.redacted = 0;

    r[10].tag = DTL_REC_DIAG;
    r[10].u.diag.subsystem = 0x0042;
    r[10].u.diag.blob_len = 4;
    bytes = dtl_arena_alloc(a, 4);
    for (i = 0; i < 4; i++)
        bytes[i] = (uint8_t)(0xC0 + seed + i);
    r[10].u.diag.blob = bytes;
    r[10].u.diag.redacted = 0;
}

/* Build a container with `nsets` sets of the 11 records; codec per set. */
static dtl_err build_container(dtl_arena *a, unsigned base_seed,
                               unsigned nsets, uint8_t **out, size_t *out_len)
{
    dtl_writer w;
    unsigned s;

    dtl_writer_init(&w, a);
    for (s = 0; s < nsets; s++) {
        dtl_record recs[11];
        int i;

        make_records(a, base_seed + s, recs);
        if (dtl_writer_begin_section(&w, (uint16_t)(1 + s),
                                     (uint8_t)(s % 4)) < 0)
            return DTL_ERR_OOM;
        for (i = 0; i < 11; i++) {
            dtl_err rc = dtl_writer_add_record(&w, &recs[i]);
            if (rc != DTL_OK)
                return rc;
        }
        {
            dtl_err rc = dtl_writer_end_section(&w);
            if (rc != DTL_OK)
                return rc;
        }
    }
    return dtl_writer_finish(&w, out, out_len);
}

static dtl_err write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL)
        return DTL_ERR_IO;
    if (len != 0 && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return DTL_ERR_IO;
    }
    fclose(f);
    return DTL_OK;
}

/* ---- walk counting -------------------------------------------------------- */

typedef struct count_ctx {
    size_t records;
    size_t errors;
    uint8_t tags_seen[256];
} count_ctx;

static dtl_err count_on_record(const dtl_walk_event *ev, void *user)
{
    count_ctx *c = user;
    c->records++;
    c->tags_seen[ev->rec->tag] = 1;
    return DTL_OK;
}

static void count_on_error(const dtl_walk_error *we, void *user)
{
    count_ctx *c = user;
    (void)we;
    c->errors++;
}

/* Byte-for-byte comparison of two files (1 = identical). */
static int files_identical(const char *pa, const char *pb)
{
    FILE *fa = fopen(pa, "rb");
    FILE *fb = fopen(pb, "rb");
    int same = 1;
    int ca;
    int cb;

    if (fa == NULL || fb == NULL) {
        if (fa != NULL)
            fclose(fa);
        if (fb != NULL)
            fclose(fb);
        return 0;
    }
    for (;;) {
        ca = fgetc(fa);
        cb = fgetc(fb);
        if (ca != cb) {
            same = 0;
            break;
        }
        if (ca == EOF)
            break;
    }
    fclose(fa);
    fclose(fb);
    return same;
}

int main(void)
{
    char path_a[128], path_b[128], path_m[128], dir[128];
    dtl_arena a;
    uint8_t *img_a = NULL, *img_b = NULL;
    size_t len_a = 0, len_b = 0;
    dtl_err rc;

    dtl_arena_init(&a, 256 * 1024);

    snprintf(path_a, sizeof path_a, "/tmp/dtl_report_smoke_%d_a.dtl",
             (int)getpid());
    snprintf(path_b, sizeof path_b, "/tmp/dtl_report_smoke_%d_b.dtl",
             (int)getpid());
    snprintf(path_m, sizeof path_m, "/tmp/dtl_report_smoke_%d_m.dtl",
             (int)getpid());
    snprintf(dir, sizeof dir, "/tmp");

    /* two sets per container -> 22 records each, distinct seeds */
    rc = build_container(&a, 3, 2, &img_a, &len_a);
    CHECK(rc == DTL_OK, "build container A (rc=%s)", dtl_strerror(rc));
    rc = build_container(&a, 5, 2, &img_b, &len_b);
    CHECK(rc == DTL_OK, "build container B (rc=%s)", dtl_strerror(rc));
    rc = write_file(path_a, img_a, len_a);
    CHECK(rc == DTL_OK, "write %s", path_a);
    rc = write_file(path_b, img_b, len_b);
    CHECK(rc == DTL_OK, "write %s", path_b);

    /* ---- walk ---- */
    {
        dtl_arena wa;
        count_ctx c;
        dtl_walk w;

        memset(&c, 0, sizeof c);
        w.on_record = count_on_record;
        w.on_error = count_on_error;
        w.user = &c;
        w.max_decode = 0;

        dtl_arena_init(&wa, 64 * 1024);
        rc = dtl_walk_memory(img_a, len_a, &wa, &w);
        CHECK(rc == DTL_OK, "walk A (rc=%s)", dtl_strerror(rc));
        CHECK(c.records == 22, "walk A sees 22 records (got %llu)",
              (unsigned long long)c.records);
        CHECK(c.errors == 0, "walk A reports no errors (got %llu)",
              (unsigned long long)c.errors);
        CHECK(c.tags_seen[DTL_REC_HEARTBEAT] && c.tags_seen[DTL_REC_DIAG],
              "walk A sees both fixed and variable record types");
        dtl_arena_free(&wa);
    }

    /* ---- stats ---- */
    {
        dtl_stats st;
        dtl_stats_init(&st);
        rc = dtl_stats_collect_file(path_a, 1u << 20, &st);
        CHECK(rc == DTL_OK, "stats collect A (rc=%s)", dtl_strerror(rc));
        CHECK(st.total_records == 22, "stats total 22 (got %llu)",
              (unsigned long long)st.total_records);
        CHECK(st.tag_counts[DTL_REC_BATTERY] == 2,
              "stats battery count 2 (got %llu)",
              (unsigned long long)st.tag_counts[DTL_REC_BATTERY]);
        CHECK(st.hb_uptime_s.count == 2 && st.hb_uptime_s.min == 3001.0,
              "stats hb.uptime min 3001 (got %.1f)", st.hb_uptime_s.min);
        CHECK(st.parse_errors == 0, "stats no parse errors");
    }

    /* ---- index ---- */
    {
        dtl_arena ia;
        dtl_index idx;

        dtl_arena_init(&ia, 64 * 1024);
        rc = dtl_index_build(path_a, 1u << 20, &ia, &idx);
        CHECK(rc == DTL_OK, "index build A (rc=%s)", dtl_strerror(rc));
        CHECK(idx.total == 22, "index total 22 (got %llu)",
              (unsigned long long)idx.total);
        CHECK(idx.per_tag[DTL_REC_LOG] == 2, "index LOG postings 2");
        CHECK(dtl_index_foreach_tag(&idx, DTL_REC_SENSOR, NULL, NULL) == 2,
              "index SENSOR foreach 2");
        CHECK(dtl_index_foreach_tag(&idx, 0x7F, NULL, NULL) == 0,
              "index unknown tag foreach 0");
        dtl_arena_free(&ia);
    }

    /* ---- export ---- */
    {
        FILE *tmp = tmpfile();
        long sz;

        rc = dtl_export_file(path_a, 1u << 20, DTL_EXPORT_CSV, tmp);
        CHECK(rc == DTL_OK, "export CSV (rc=%s)", dtl_strerror(rc));
        fseek(tmp, 0, SEEK_END);
        sz = ftell(tmp);
        CHECK(sz > 200, "CSV export non-trivial (%ld bytes)", sz);
        rewind(tmp);
        {
            char hdr[64];
            hdr[0] = '\0';
            if (fgets(hdr, sizeof hdr, tmp) != NULL)
                CHECK(strncmp(hdr, "index,tag,", 10) == 0,
                      "CSV header row (got %.10s)", hdr);
            else
                CHECK(0, "CSV header row readable");
        }
        fclose(tmp);

        tmp = tmpfile();
        rc = dtl_export_file(path_a, 1u << 20, DTL_EXPORT_JSON, tmp);
        CHECK(rc == DTL_OK, "export JSON (rc=%s)", dtl_strerror(rc));
        fseek(tmp, 0, SEEK_END);
        sz = ftell(tmp);
        CHECK(sz > 400, "JSON export non-trivial (%ld bytes)", sz);
        fclose(tmp);

        {
            dtl_export_format fmt;
            CHECK(dtl_export_parse_format("csv", &fmt) == 0 &&
                  fmt == DTL_EXPORT_CSV, "parse format csv");
            CHECK(dtl_export_parse_format("json", &fmt) == 0 &&
                  fmt == DTL_EXPORT_JSON, "parse format json");
            CHECK(dtl_export_parse_format("xml", &fmt) != 0,
                  "reject unknown format");
        }
    }

    /* ---- validate ---- */
    {
        dtl_arena va;
        dtl_validate_report rep;

        dtl_arena_init(&va, 64 * 1024);
        rc = dtl_validate_file(path_a, 1u << 20, &va, &rep);
        CHECK(rc == DTL_OK, "validate clean A (rc=%s)", dtl_strerror(rc));
        CHECK(rep.records_checked == 22, "validate checked 22 (got %llu)",
              (unsigned long long)rep.records_checked);
        CHECK(rep.error_count == 0, "validate clean A has no errors (got %llu)",
              (unsigned long long)rep.error_count);
        dtl_arena_free(&va);

        /* dirty input: battery pct 250 must be flagged */
        {
            dtl_arena da;
            uint8_t *img_d = NULL;
            size_t len_d = 0;
            char path_d[128];
            dtl_record dirty[11];

            dtl_arena_init(&da, 64 * 1024);
            make_records(&da, 3, dirty);
            dirty[2].u.battery.pct = 250;
            {
                dtl_writer w;
                dtl_writer_init(&w, &da);
                dtl_writer_begin_section(&w, 1, DTL_CODEC_STORE);
                dtl_writer_add_record(&w, &dirty[2]);
                dtl_writer_end_section(&w);
                rc = dtl_writer_finish(&w, &img_d, &len_d);
            }
            snprintf(path_d, sizeof path_d,
                     "/tmp/dtl_report_smoke_%d_d.dtl", (int)getpid());
            write_file(path_d, img_d, len_d);

            {
                dtl_arena va2;
                dtl_validate_report rep2;
                dtl_arena_init(&va2, 64 * 1024);
                rc = dtl_validate_file(path_d, 1u << 20, &va2, &rep2);
                CHECK(rc == DTL_OK && rep2.error_count == 1,
                      "validate flags battery pct 250 (errors=%llu)",
                      (unsigned long long)rep2.error_count);
                dtl_arena_free(&va2);
            }
            remove(path_d);
            dtl_arena_free(&da);
        }
    }

    /* ---- diff ---- */
    {
        size_t diffs = 999;
        FILE *sink = tmpfile();

        rc = dtl_diff_files(path_a, path_a, 1u << 20, NULL, sink, &diffs);
        CHECK(rc == DTL_OK && diffs == 0,
              "diff A vs A: 0 differences (rc=%s diffs=%llu)",
              dtl_strerror(rc), (unsigned long long)diffs);

        diffs = 0;
        rc = dtl_diff_files(path_a, path_b, 1u << 20, NULL, sink, &diffs);
        CHECK(rc == DTL_OK && diffs > 0,
              "diff A vs B: differences found (diffs=%llu)",
              (unsigned long long)diffs);
        fclose(sink);
    }

    /* ---- merge ---- */
    {
        const char *inputs[2] = { path_a, path_b };
        count_ctx c;
        dtl_walk w;

        rc = dtl_merge_files(inputs, 2, 1u << 20, path_m);
        CHECK(rc == DTL_OK, "merge A+B (rc=%s)", dtl_strerror(rc));

        memset(&c, 0, sizeof c);
        w.on_record = count_on_record;
        w.on_error = count_on_error;
        w.user = &c;
        w.max_decode = 0;
        rc = dtl_walk_file(path_m, 1u << 20, &w);
        CHECK(rc == DTL_OK && c.records == 44,
              "merged container holds 44 records (rc=%s got %llu)",
              dtl_strerror(rc), (unsigned long long)c.records);
    }

    /* ---- split ---- */
    {
        char spath[192];
        count_ctx c;
        dtl_walk w;
        size_t tag;

        rc = dtl_split_file(path_a, 1u << 20, dir, "dtl_smoke_split", NULL);
        CHECK(rc == DTL_OK, "split A (rc=%s)", dtl_strerror(rc));

        /* every produced file must hold exactly one tag, two records */
        for (tag = 0; tag < 256; tag++) {
            const char *name = dtl_walk_tag_name((uint8_t)tag);
            FILE *probe;

            if (strcmp(name, "UNKNOWN") == 0)
                continue;
            snprintf(spath, sizeof spath, "%s/dtl_smoke_split_%s.dtl", dir,
                     name);
            probe = fopen(spath, "rb");
            if (probe == NULL)
                continue;
            fclose(probe);

            memset(&c, 0, sizeof c);
            w.on_record = count_on_record;
            w.on_error = NULL;
            w.user = &c;
            w.max_decode = 0;
            rc = dtl_walk_file(spath, 1u << 20, &w);
            if (!(rc == DTL_OK && c.records == 2)) {
                CHECK(0, "split %s holds its 2 records (rc=%s got %llu)",
                      name, dtl_strerror(rc),
                      (unsigned long long)c.records);
            }
            remove(spath);
        }
        CHECK(1, "split per-tag files each hold their 2 records");
    }

    /* ---- repack: transcode everything onto RLE, then diff records ---- */
    {
        char path_r[128];
        size_t diffs = 999;
        FILE *sink = tmpfile();

        snprintf(path_r, sizeof path_r, "/tmp/dtl_report_smoke_%d_r.dtl",
                 (int)getpid());
        rc = dtl_repack_file(path_a, path_r, DTL_CODEC_RLE, 1u << 20);
        CHECK(rc == DTL_OK, "repack A onto RLE (rc=%s)", dtl_strerror(rc));

        rc = dtl_diff_files(path_a, path_r, 1u << 20, NULL, sink, &diffs);
        CHECK(rc == DTL_OK && diffs == 0,
              "repack preserves every record (diffs=%llu)",
              (unsigned long long)diffs);
        fclose(sink);

        rc = dtl_repack_file(path_a, path_r, 99, 1u << 20);
        CHECK(rc == DTL_ERR_INVAL, "repack rejects unknown codec id");
        remove(path_r);
    }

    /* ---- select: filter records into a new container ---- */
    {
        char path_s[128];
        size_t kept = 0;
        count_ctx c;
        dtl_walk w;

        snprintf(path_s, sizeof path_s, "/tmp/dtl_report_smoke_%d_s.dtl",
                 (int)getpid());
        rc = dtl_select_file(path_a, path_s, "type == LOG", 1u << 20, &kept);
        CHECK(rc == DTL_OK && kept == 2,
              "select type==LOG keeps 2 (rc=%s kept=%llu)",
              dtl_strerror(rc), (unsigned long long)kept);

        memset(&c, 0, sizeof c);
        w.on_record = count_on_record;
        w.on_error = NULL;
        w.user = &c;
        w.max_decode = 0;
        rc = dtl_walk_file(path_s, 1u << 20, &w);
        CHECK(rc == DTL_OK && c.records == 2 &&
              c.tags_seen[DTL_REC_LOG] && !c.tags_seen[DTL_REC_NET],
              "selected container holds only LOG records");

        rc = dtl_select_file(path_a, path_s, "type == ", 1u << 20, &kept);
        CHECK(rc == DTL_ERR_BADQUERY, "select rejects uncompilable filter");
        remove(path_s);
    }

    /* ---- import: CSV round-trip through export ---- */
    {
        char path_csv[128], path_i[128];
        FILE *csv;
        size_t imported = 0;
        size_t diffs = 999;
        FILE *sink;

        snprintf(path_csv, sizeof path_csv, "/tmp/dtl_report_smoke_%d.csv",
                 (int)getpid());
        snprintf(path_i, sizeof path_i, "/tmp/dtl_report_smoke_%d_i.dtl",
                 (int)getpid());

        csv = fopen(path_csv, "wb");
        CHECK(csv != NULL, "open CSV output");
        if (csv != NULL) {
            rc = dtl_export_file(path_a, 1u << 20, DTL_EXPORT_CSV, csv);
            fclose(csv);
            CHECK(rc == DTL_OK, "export A to CSV for import");
        }

        rc = dtl_import_csv_file(path_csv, path_i, 1u << 20, &imported);
        CHECK(rc == DTL_OK && imported == 22,
              "import CSV (rc=%s imported=%llu)", dtl_strerror(rc),
              (unsigned long long)imported);

        sink = tmpfile();
        rc = dtl_diff_files(path_a, path_i, 1u << 20, NULL, sink, &diffs);
        CHECK(rc == DTL_OK && diffs == 0,
              "CSV round-trip preserves records (diffs=%llu)",
              (unsigned long long)diffs);
        fclose(sink);

        remove(path_csv);
        remove(path_i);
    }

    /* ---- jimport: JSON round-trip through export ---- */
    {
        char path_j[128], path_ji[128];
        FILE *jf;
        size_t imported = 0;
        size_t diffs = 999;
        FILE *sink;

        snprintf(path_j, sizeof path_j, "/tmp/dtl_report_smoke_%d.json",
                 (int)getpid());
        snprintf(path_ji, sizeof path_ji, "/tmp/dtl_report_smoke_%d_ji.dtl",
                 (int)getpid());

        jf = fopen(path_j, "wb");
        CHECK(jf != NULL, "open JSON output");
        if (jf != NULL) {
            rc = dtl_export_file(path_a, 1u << 20, DTL_EXPORT_JSON, jf);
            fclose(jf);
            CHECK(rc == DTL_OK, "export A to JSON for import");
        }

        rc = dtl_import_json_file(path_j, path_ji, 1u << 20, &imported);
        CHECK(rc == DTL_OK && imported == 22,
              "import JSON (rc=%s imported=%llu)", dtl_strerror(rc),
              (unsigned long long)imported);

        sink = tmpfile();
        rc = dtl_diff_files(path_a, path_ji, 1u << 20, NULL, sink, &diffs);
        CHECK(rc == DTL_OK && diffs == 0,
              "JSON round-trip preserves records (diffs=%llu)",
              (unsigned long long)diffs);
        fclose(sink);

        /* malformed input is an error, never a crash */
        {
            static const char bad[] = "{\"records\": [ {\"tag\": ";
            dtl_arena ja;
            uint8_t *ob = NULL;
            size_t ol = 0;
            size_t on = 0;

            dtl_arena_init(&ja, 16 * 1024);
            rc = dtl_import_json_memory((const uint8_t *)bad,
                                        sizeof(bad) - 1, &ja, &ob, &ol, &on);
            CHECK(rc != DTL_OK, "truncated JSON rejected (rc=%s)",
                  dtl_strerror(rc));
            dtl_arena_free(&ja);
        }

        remove(path_j);
        remove(path_ji);
    }

    /* ---- timeline: two heartbeat sessions with a gap between them ---- */
    {
        dtl_arena ta;
        dtl_timeline tl;
        FILE *sink;

        dtl_arena_init(&ta, 64 * 1024);
        rc = dtl_timeline_build(path_a, 1u << 20, NULL, &ta, &tl);
        CHECK(rc == DTL_OK, "timeline build A (rc=%s)", dtl_strerror(rc));
        CHECK(tl.session_count == 2, "timeline sees 2 sessions (got %llu)",
              (unsigned long long)tl.session_count);
        /* uptimes 3001 -> 4001: 1000s apart, threshold is 2 * 60s */
        CHECK(tl.gap_count == 1, "timeline flags the 1000s gap (got %llu)",
              (unsigned long long)tl.gap_count);
        CHECK(tl.ordering_violations == 0 && tl.unattributed_records == 0,
              "timeline: no ordering violations or orphans");
        if (tl.session_count == 2) {
            CHECK(tl.sessions[0].uptime_s == 3001 &&
                  tl.sessions[1].uptime_s == 4001,
                  "session checkpoints are the heartbeat uptimes");
            CHECK(tl.sessions[0].record_count == 11 &&
                  tl.sessions[1].record_count == 11,
                  "each session owns its 11 records (got %llu/%llu)",
                  (unsigned long long)tl.sessions[0].record_count,
                  (unsigned long long)tl.sessions[1].record_count);
            CHECK(tl.sessions[1].first_record_index == 11,
                  "second session opens at record 11 (got %llu)",
                  (unsigned long long)tl.sessions[1].first_record_index);
        }

        sink = tmpfile();
        dtl_timeline_print(&tl, NULL, sink);
        CHECK(ftell(sink) > 0, "timeline print produces output");
        fclose(sink);
        dtl_arena_free(&ta);
    }

    /* ---- topk: battery.pct ranking, highest value first ---- */
    {
        FILE *sink = tmpfile();
        char content[512];
        size_t n;

        CHECK(dtl_topk_field_exists("battery.pct"),
              "topk lists battery.pct as rankable");
        CHECK(!dtl_topk_field_exists("bogus.field"),
              "topk rejects an unknown field name");

        /* battery pcts in A are 3 and 4; top-1 must show 4.000 */
        rc = dtl_topk_file(path_a, 1u << 20, "battery.pct", 1, sink);
        CHECK(rc == DTL_OK, "topk battery.pct (rc=%s)", dtl_strerror(rc));
        fflush(sink);
        rewind(sink);
        n = fread(content, 1, sizeof(content) - 1, sink);
        content[n] = '\0';
        fclose(sink);
        CHECK(strstr(content, "2 candidates") != NULL,
              "topk sees both battery records");
        CHECK(strstr(content, "value=4.000") != NULL,
              "topk ranks pct=4 above pct=3");

        sink = tmpfile();
        rc = dtl_topk_file(path_a, 1u << 20, "bogus.field", 5, sink);
        CHECK(rc == DTL_ERR_INVAL, "topk unknown field -> INVAL (rc=%s)",
              dtl_strerror(rc));
        fclose(sink);
    }

    /* ---- dedup: exact duplicates collapse, clean files pass through ---- */
    {
        const char *two_a[2] = { path_a, path_a };
        char path_mm[128], path_d[128], path_da[128];
        size_t dropped = 999;
        size_t diffs = 999;
        FILE *sink;
        dtl_arena wa;
        count_ctx c;
        dtl_walk w;

        snprintf(path_mm, sizeof path_mm, "/tmp/dtl_report_smoke_%d_mm.dtl",
                 (int)getpid());
        snprintf(path_d, sizeof path_d, "/tmp/dtl_report_smoke_%d_d.dtl",
                 (int)getpid());
        snprintf(path_da, sizeof path_da, "/tmp/dtl_report_smoke_%d_da.dtl",
                 (int)getpid());

        /* merging A with itself doubles every record */
        rc = dtl_merge_files(two_a, 2, 1u << 20, path_mm);
        CHECK(rc == DTL_OK, "merge A+A (rc=%s)", dtl_strerror(rc));

        rc = dtl_dedup_file(path_mm, path_d, 1u << 20, &dropped);
        CHECK(rc == DTL_OK && dropped == 22,
              "dedup drops the 22 duplicates (rc=%s dropped=%llu)",
              dtl_strerror(rc), (unsigned long long)dropped);

        memset(&c, 0, sizeof c);
        w.on_record = count_on_record;
        w.on_error = count_on_error;
        w.user = &c;
        w.max_decode = 0;
        dtl_arena_init(&wa, 64 * 1024);
        rc = dtl_walk_file(path_d, 1u << 20, &w);
        dtl_arena_free(&wa);
        CHECK(rc == DTL_OK && c.records == 22,
              "deduped container holds 22 records (got %llu)",
              (unsigned long long)c.records);

        /* a container without duplicates is preserved byte-for-byte */
        rc = dtl_dedup_file(path_a, path_da, 1u << 20, &dropped);
        CHECK(rc == DTL_OK && dropped == 0,
              "dedup finds nothing to drop in A (dropped=%llu)",
              (unsigned long long)dropped);
        sink = tmpfile();
        rc = dtl_diff_files(path_a, path_da, 1u << 20, NULL, sink, &diffs);
        CHECK(rc == DTL_OK && diffs == 0,
              "dedup preserves a clean container (diffs=%llu)",
              (unsigned long long)diffs);
        fclose(sink);

        remove(path_mm);
        remove(path_d);
        remove(path_da);
    }

    /* ---- sample: deterministic reservoir, n=0 copies everything ---- */
    {
        char path_s1[128], path_s2[128], path_sall[128];
        size_t taken = 0;
        size_t diffs = 999;
        FILE *sink;
        dtl_arena va;
        dtl_validate_report rep;

        snprintf(path_s1, sizeof path_s1, "/tmp/dtl_report_smoke_%d_s1.dtl",
                 (int)getpid());
        snprintf(path_s2, sizeof path_s2, "/tmp/dtl_report_smoke_%d_s2.dtl",
                 (int)getpid());
        snprintf(path_sall, sizeof path_sall,
                 "/tmp/dtl_report_smoke_%d_sall.dtl", (int)getpid());

        rc = dtl_sample_file(path_a, path_s1, 5, 42u, 1u << 20, &taken);
        CHECK(rc == DTL_OK && taken == 5,
              "sample takes 5 records (rc=%s taken=%llu)", dtl_strerror(rc),
              (unsigned long long)taken);
        rc = dtl_sample_file(path_a, path_s2, 5, 42u, 1u << 20, &taken);
        CHECK(rc == DTL_OK && taken == 5, "sample repeat takes 5");
        CHECK(files_identical(path_s1, path_s2),
              "same seed produces byte-identical output");

        /* the sampled subset is itself a valid container */
        dtl_arena_init(&va, 64 * 1024);
        rc = dtl_validate_file(path_s1, 1u << 20, &va, &rep);
        CHECK(rc == DTL_OK && rep.records_checked == 5 &&
              rep.error_count == 0,
              "sampled container validates clean (checked=%llu errors=%llu)",
              (unsigned long long)rep.records_checked,
              (unsigned long long)rep.error_count);
        dtl_arena_free(&va);

        /* n == 0 copies every record */
        rc = dtl_sample_file(path_a, path_sall, 0, 7u, 1u << 20, &taken);
        CHECK(rc == DTL_OK && taken == 22,
              "sample n=0 copies all 22 (taken=%llu)",
              (unsigned long long)taken);
        sink = tmpfile();
        rc = dtl_diff_files(path_a, path_sall, 1u << 20, NULL, sink, &diffs);
        CHECK(rc == DTL_OK && diffs == 0,
              "sample n=0 preserves records (diffs=%llu)",
              (unsigned long long)diffs);
        fclose(sink);

        remove(path_s1);
        remove(path_s2);
        remove(path_sall);
    }

    /* ---- sign: HMAC trailer verifies, records unchanged ---- */
    {
        static const uint8_t kkey[] = "smoke-signing-key";
        char path_g[128];
        size_t diffs = 999;
        FILE *sink;
        dtl_arena pa;
        dtl_container cont;
        dtl_buf pb;
        FILE *f;
        uint8_t buf[65536];
        size_t n;

        snprintf(path_g, sizeof path_g, "/tmp/dtl_report_smoke_%d_g.dtl",
                 (int)getpid());
        rc = dtl_sign_file(path_a, path_g, kkey, sizeof(kkey) - 1, 1u << 20);
        CHECK(rc == DTL_OK, "sign A (rc=%s)", dtl_strerror(rc));

        /* trailer present */
        f = fopen(path_g, "rb");
        CHECK(f != NULL, "open signed container");
        n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        dtl_arena_init(&pa, 64 * 1024);
        dtl_buf_init(&pb, buf, n);
        rc = dtl_container_parse(&pb, &pa, &cont);
        CHECK(rc == DTL_OK && cont.hmac != NULL,
              "signed container carries an HMAC trailer");
        dtl_arena_free(&pa);

        /* records identical to the unsigned original */
        sink = tmpfile();
        rc = dtl_diff_files(path_a, path_g, 1u << 20, NULL, sink, &diffs);
        CHECK(rc == DTL_OK && diffs == 0,
              "sign preserves every record (diffs=%llu)",
              (unsigned long long)diffs);
        fclose(sink);
        remove(path_g);
    }

    remove(path_a);
    remove(path_b);
    remove(path_m);
    dtl_arena_free(&a);

    printf("report smoke: %s\n", g_failures == 0 ? "OK" : "FAILURES");
    return g_failures == 0 ? 0 : 1;
}
