// report_fuzzer -- exercises the full report subsystem end to end.
//
// Fuzz input is tried three ways (CSV import, JSON import, raw container).
// Each resulting container is exercised by: walk+export, validate, dedup,
// timeline, sample, and merge — covering the complete report pipeline
// including all payload-lifetime, generational-pool, and reservoir paths.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

extern "C" {
#include "core/arena.h"
#include "report/dedup.h"
#include "report/export.h"
#include "report/import.h"
#include "report/jimport.h"
#include "report/merge.h"
#include "report/sample.h"
#include "report/timeline.h"
#include "report/validate.h"
#include "report/walk.h"
}

namespace {

struct Pipeline {
    FILE  *csv;
    FILE  *json;
    char  *csv_buf;
    char  *json_buf;
    size_t csv_len;
    size_t json_len;
    size_t records;
};

dtl_err OnRecord(const dtl_walk_event *ev, void *user) {
    Pipeline *p = static_cast<Pipeline *>(user);
    if (p->csv)
        dtl_export_record(p->csv, DTL_EXPORT_CSV, ev->rec, p->records);
    if (p->json)
        dtl_export_record(p->json, DTL_EXPORT_JSON, ev->rec, p->records);
    p->records++;
    return DTL_OK;
}

/* Write bytes to a fresh temp file; returns 0 on success. */
static int bytes_to_tmp(const uint8_t *b, size_t n, char *tmpl) {
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    ssize_t w = write(fd, b, n);
    close(fd);
    if (w != (ssize_t)n) { remove(tmpl); return -1; }
    return 0;
}

void ExerciseContainer(const uint8_t *bytes, size_t len) {
    if (!bytes || !len) return;

    dtl_arena arena;
    dtl_arena_init(&arena, 64 * 1024);

    /* walk + export (CSV + JSON) */
    {
        Pipeline p = {};
        p.csv  = open_memstream(&p.csv_buf, &p.csv_len);
        p.json = open_memstream(&p.json_buf, &p.json_len);
        dtl_walk w;
        w.on_record  = OnRecord;
        w.on_error   = nullptr;
        w.user       = &p;
        w.max_decode = 0;
        dtl_walk_memory(bytes, len, &arena, &w);
        if (p.csv)  fclose(p.csv);
        if (p.json) fclose(p.json);
        free(p.csv_buf);
        free(p.json_buf);
    }

    /* deep validator */
    {
        dtl_validate_report rep;
        dtl_validate_memory(bytes, len, &arena, &rep);
    }

    /* dedup: retain-then-compare pass
     * Triggers: event-UAF (#1), config-UAF (#2), keyref-UAF (#5),
     *           diag-pool-eviction-UAF (#10), sensor-pool-UAF (#11). */
    {
        char in[]  = "/tmp/rfi_XXXXXX";
        char out[] = "/tmp/rfo_XXXXXX";
        int ofd = mkstemp(out);
        if (ofd >= 0) close(ofd);
        if (bytes_to_tmp(bytes, len, in) == 0) {
            size_t dropped = 0;
            dtl_dedup_file(in, out, 1u << 20, &dropped);
            remove(in);
        }
        remove(out);
    }

    /* merge: per-tag grow path
     * Triggers: merge-stale-base (#8). */
    {
        char in[]  = "/tmp/rmi_XXXXXX";
        char out[] = "/tmp/rmo_XXXXXX";
        int ofd = mkstemp(out);
        if (ofd >= 0) close(ofd);
        if (bytes_to_tmp(bytes, len, in) == 0) {
            const char *paths[1] = { in };
            dtl_merge_files(paths, 1, 1u << 20, out);
            remove(in);
        }
        remove(out);
    }

    /* sample: reservoir algorithm R, n=5, seed=1
     * Triggers: reservoir-off-by-one (#7). */
    {
        char in[]  = "/tmp/rsi_XXXXXX";
        char out[] = "/tmp/rso_XXXXXX";
        int ofd = mkstemp(out);
        if (ofd >= 0) close(ofd);
        if (bytes_to_tmp(bytes, len, in) == 0) {
            size_t taken = 0;
            dtl_sample_file(in, out, 5, 1, 1u << 20, &taken);
            remove(in);
        }
        remove(out);
    }

    /* timeline: per-session aggregation
     * Triggers: timeline-uninit (#3, MSan). */
    {
        char in[] = "/tmp/rti_XXXXXX";
        if (bytes_to_tmp(bytes, len, in) == 0) {
            dtl_timeline tl;
            dtl_timeline_build(in, 1u << 20, nullptr, &arena, &tl);
            remove(in);
        }
    }

    dtl_arena_free(&arena);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data || !size) return 0;

    /* Path 1: CSV import -> container -> full pipeline */
    {
        dtl_arena arena;
        dtl_arena_init(&arena, 64 * 1024);
        uint8_t *out = nullptr;
        size_t out_len = 0, records = 0;
        if (dtl_import_csv_memory(data, size, &arena, &out, &out_len,
                                  &records) == DTL_OK)
            ExerciseContainer(out, out_len);
        dtl_arena_free(&arena);
    }

    /* Path 2: JSON import -> container -> full pipeline
     * Triggers: json-sensor-overflow (#4), json-config-overflow (#9). */
    {
        dtl_arena arena;
        dtl_arena_init(&arena, 64 * 1024);
        uint8_t *out = nullptr;
        size_t out_len = 0, records = 0;
        if (dtl_import_json_memory(data, size, &arena, &out, &out_len,
                                   &records) == DTL_OK)
            ExerciseContainer(out, out_len);
        dtl_arena_free(&arena);
    }

    /* Path 3: raw serialized container -> full pipeline
     * Triggers: lz77-offset-underflow (#12) via codec decode in the walk,
     *           csv-diag-overread (#6) when input is a valid container with
     *           a diag section whose blob_len exceeds its actual allocation. */
    ExerciseContainer(data, size);

    return 0;
}
