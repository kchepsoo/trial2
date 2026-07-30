#include "report/diff.h"

#include <stdio.h>
#include <string.h>

#include "report/walk.h"

/* ---- record collection ---------------------------------------------------- */

typedef struct dtl_record_vec {
    dtl_record *recs;      /* arena-allocated array */
    size_t      count;
    size_t      cap;
    dtl_arena  *a;
} dtl_record_vec;

static dtl_err dtl_vec_push(dtl_record_vec *v, const dtl_record *rec)
{
    if (v->count == v->cap) {
        size_t new_cap = v->cap ? v->cap * 2 : 64;
        dtl_record *grown = dtl_arena_alloc(v->a, new_cap * sizeof(*grown));
        if (grown == NULL)
            return DTL_ERR_OOM;
        if (v->count != 0)
            memcpy(grown, v->recs, v->count * sizeof(*grown));
        v->recs = grown;
        v->cap = new_cap;
    }
    v->recs[v->count++] = *rec; /* shallow: payloads stay in the walk arena */
    return DTL_OK;
}

static dtl_err dtl_vec_on_record(const dtl_walk_event *ev, void *user)
{
    return dtl_vec_push(user, ev->rec);
}

static dtl_err dtl_diff_collect(const uint8_t *data, size_t len, dtl_arena *a,
                                dtl_record_vec *v)
{
    dtl_walk w;

    memset(v, 0, sizeof(*v));
    v->a = a;

    w.on_record = dtl_vec_on_record;
    w.on_error = NULL;
    w.user = v;
    w.max_decode = 0;
    return dtl_walk_memory(data, len, a, &w);
}

/* ---- field comparison ------------------------------------------------------ */

static int dtl_bytes_equal(const uint8_t *a, size_t an,
                           const uint8_t *b, size_t bn)
{
    if (an != bn)
        return 0;
    if (an == 0)
        return 1;
    return memcmp(a, b, an) == 0;
}

static int dtl_str_equal(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
        return a == b;
    return strcmp(a, b) == 0;
}

/* Returns 0 when equal; otherwise writes a short reason into why. */
static int dtl_record_compare(const dtl_record *ra, const dtl_record *rb,
                              int ignore_redaction, char *why, size_t why_cap)
{
    if (ra->tag != rb->tag) {
        snprintf(why, why_cap, "tag %s != %s", dtl_walk_tag_name(ra->tag),
                 dtl_walk_tag_name(rb->tag));
        return 1;
    }

#define DTL_DIFF_U(field, fmt)                                                \
    do {                                                                      \
        if (ra->field != rb->field) {                                         \
            snprintf(why, why_cap, "%s " fmt " != " fmt, #field, ra->field,   \
                     rb->field);                                              \
            return 1;                                                         \
        }                                                                     \
    } while (0)

    switch (ra->tag) {
    case DTL_REC_HEARTBEAT:
        DTL_DIFF_U(u.heartbeat.uptime_s, "%u");
        DTL_DIFF_U(u.heartbeat.seq, "%u");
        break;
    case DTL_REC_SENSOR: {
        uint8_t i;
        DTL_DIFF_U(u.sensor.sensor_id, "%u");
        DTL_DIFF_U(u.sensor.count, "%u");
        for (i = 0; i < ra->u.sensor.count; i++) {
            if (ra->u.sensor.samples[i] != rb->u.sensor.samples[i]) {
                snprintf(why, why_cap, "sensor.samples[%u] %.9g != %.9g", i,
                         (double)ra->u.sensor.samples[i],
                         (double)rb->u.sensor.samples[i]);
                return 1;
            }
        }
        break;
    }
    case DTL_REC_EVENT:
        DTL_DIFF_U(u.event.code, "%u");
        if (!dtl_bytes_equal(ra->u.event.payload, ra->u.event.payload_len,
                             rb->u.event.payload, rb->u.event.payload_len)) {
            snprintf(why, why_cap, "event payload differs (%u vs %u bytes)",
                     ra->u.event.payload_len, rb->u.event.payload_len);
            return 1;
        }
        break;
    case DTL_REC_DIAG:
        DTL_DIFF_U(u.diag.subsystem, "%u");
        if (!ignore_redaction)
            DTL_DIFF_U(u.diag.redacted, "%u");
        if (!dtl_bytes_equal(ra->u.diag.blob, ra->u.diag.blob_len,
                             rb->u.diag.blob, rb->u.diag.blob_len)) {
            snprintf(why, why_cap, "diag blob differs (%u vs %u bytes)",
                     ra->u.diag.blob_len, rb->u.diag.blob_len);
            return 1;
        }
        break;
    case DTL_REC_GEO:
        DTL_DIFF_U(u.geo.lat_e7, "%d");
        DTL_DIFF_U(u.geo.lon_e7, "%d");
        DTL_DIFF_U(u.geo.alt_mm, "%d");
        break;
    case DTL_REC_BATTERY:
        DTL_DIFF_U(u.battery.pct, "%u");
        DTL_DIFF_U(u.battery.temp_c_e1, "%d");
        DTL_DIFF_U(u.battery.cycles, "%u");
        break;
    case DTL_REC_NET:
        DTL_DIFF_U(u.net.iface_id, "%u");
        DTL_DIFF_U(u.net.rx_bytes, "%u");
        DTL_DIFF_U(u.net.tx_bytes, "%u");
        DTL_DIFF_U(u.net.rx_pkts, "%u");
        DTL_DIFF_U(u.net.tx_pkts, "%u");
        break;
    case DTL_REC_LOG:
        DTL_DIFF_U(u.log.severity, "%u");
        if (!dtl_str_equal(ra->u.log.msg, rb->u.log.msg)) {
            snprintf(why, why_cap, "log message differs");
            return 1;
        }
        break;
    case DTL_REC_CONFIG: {
        uint8_t i;
        DTL_DIFF_U(u.config.pair_count, "%u");
        for (i = 0; i < ra->u.config.pair_count; i++) {
            if (!dtl_str_equal(ra->u.config.pairs[i].key,
                               rb->u.config.pairs[i].key) ||
                !dtl_str_equal(ra->u.config.pairs[i].value,
                               rb->u.config.pairs[i].value)) {
                snprintf(why, why_cap, "config pair %u differs", i);
                return 1;
            }
        }
        break;
    }
    case DTL_REC_KEYREF:
        DTL_DIFF_U(u.keyref.slot_id, "%u");
        if (!ignore_redaction)
            DTL_DIFF_U(u.keyref.redacted, "%u");
        if (!ignore_redaction &&
            !dtl_str_equal(ra->u.keyref.label, rb->u.keyref.label)) {
            snprintf(why, why_cap, "keyref label differs");
            return 1;
        }
        break;
    case DTL_REC_FIRMWARE:
        DTL_DIFF_U(u.firmware.major, "%u");
        DTL_DIFF_U(u.firmware.minor, "%u");
        DTL_DIFF_U(u.firmware.patch, "%u");
        if (!dtl_bytes_equal(ra->u.firmware.hash, 8, rb->u.firmware.hash, 8)) {
            snprintf(why, why_cap, "firmware hash differs");
            return 1;
        }
        break;
    default:
        break;
    }
#undef DTL_DIFF_U
    return 0;
}

int dtl_diff_records_equal(const dtl_record *ra, const dtl_record *rb,
                           int ignore_redaction)
{
    char why[96];
    return dtl_record_compare(ra, rb, ignore_redaction, why, sizeof(why)) == 0;
}

/* ---- top level -------------------------------------------------------------- */

static dtl_err dtl_diff_read(const char *path, size_t max_file, dtl_arena *a,
                             uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long sz;
    size_t n;

    if (f == NULL)
        return DTL_ERR_IO;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return DTL_ERR_IO; }
    sz = ftell(f);
    if (sz < 0 || (unsigned long)sz > max_file) {
        fclose(f);
        return sz < 0 ? DTL_ERR_IO : DTL_ERR_RANGE;
    }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return DTL_ERR_IO; }

    n = (size_t)sz;
    *out = dtl_arena_alloc(a, n ? n : 1);
    if (*out == NULL) {
        fclose(f);
        return DTL_ERR_OOM;
    }
    if (n != 0 && fread(*out, 1, n, f) != n) {
        fclose(f);
        return DTL_ERR_IO;
    }
    fclose(f);
    *out_len = n;
    return DTL_OK;
}

dtl_err dtl_diff_files(const char *path_a, const char *path_b,
                       size_t max_file, const dtl_diff_options *opts,
                       FILE *out, size_t *out_diffs)
{
    dtl_arena a;
    uint8_t *data_a = NULL, *data_b = NULL;
    size_t len_a = 0, len_b = 0;
    dtl_record_vec va, vb;
    dtl_err rc;
    size_t common, i, diffs = 0, reported = 0;
    int ignore_redaction = opts ? opts->ignore_redaction : 0;
    size_t max_report = opts ? opts->max_report : 0;

    dtl_arena_init(&a, 256 * 1024);

    rc = dtl_diff_read(path_a, max_file, &a, &data_a, &len_a);
    if (rc != DTL_OK)
        goto done;
    rc = dtl_diff_read(path_b, max_file, &a, &data_b, &len_b);
    if (rc != DTL_OK)
        goto done;
    rc = dtl_diff_collect(data_a, len_a, &a, &va);
    if (rc != DTL_OK)
        goto done;
    rc = dtl_diff_collect(data_b, len_b, &a, &vb);
    if (rc != DTL_OK)
        goto done;

    common = va.count < vb.count ? va.count : vb.count;
    for (i = 0; i < common; i++) {
        char why[96];
        if (dtl_record_compare(&va.recs[i], &vb.recs[i], ignore_redaction,
                               why, sizeof(why))) {
            diffs++;
            if (max_report == 0 || reported < max_report) {
                fprintf(out, "record %llu: %s\n", (unsigned long long)i, why);
                reported++;
            }
        }
    }
    for (i = common; i < va.count; i++) {
        diffs++;
        if (max_report == 0 || reported < max_report) {
            fprintf(out, "record %llu: only in %s (tag %s)\n",
                    (unsigned long long)i, path_a,
                    dtl_walk_tag_name(va.recs[i].tag));
            reported++;
        }
    }
    for (i = common; i < vb.count; i++) {
        diffs++;
        if (max_report == 0 || reported < max_report) {
            fprintf(out, "record %llu: only in %s (tag %s)\n",
                    (unsigned long long)i, path_b,
                    dtl_walk_tag_name(vb.recs[i].tag));
            reported++;
        }
    }
    if (diffs > reported)
        fprintf(out, "... %llu more differences suppressed\n",
                (unsigned long long)(diffs - reported));

    rc = DTL_OK;
done:
    if (out_diffs != NULL)
        *out_diffs = diffs;
    dtl_arena_free(&a);
    return rc;
}
