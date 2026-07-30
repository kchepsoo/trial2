#include "report/validate.h"

#include <stdarg.h>
#include <string.h>

#include "core/arena.h"
#include "report/walk.h"

static void dtl_validate_add(dtl_validate_report *rep,
                             dtl_validate_severity sev,
                             uint16_t section_index, size_t record_in_sec,
                             const char *fmt, ...)
{
    dtl_issue *is;
    va_list ap;

    if (rep->issue_count == rep->issue_cap) {
        size_t new_cap = rep->issue_cap ? rep->issue_cap * 2 : 32;
        dtl_issue *grown =
            dtl_arena_alloc(rep->a, new_cap * sizeof(*grown));
        if (grown == NULL)
            return; /* arena exhausted: keep the findings gathered so far */
        if (rep->issue_count != 0)
            memcpy(grown, rep->issues, rep->issue_count * sizeof(*grown));
        rep->issues = grown;
        rep->issue_cap = new_cap;
    }

    is = &rep->issues[rep->issue_count++];
    is->severity = sev;
    is->section_index = section_index;
    is->record_in_sec = record_in_sec;
    va_start(ap, fmt);
    vsnprintf(is->message, sizeof(is->message), fmt, ap);
    va_end(ap);

    if (sev == DTL_VALIDATE_ERROR)
        rep->error_count++;
    else if (sev == DTL_VALIDATE_WARNING)
        rep->warning_count++;
}

/* ---- per-type semantic checks ------------------------------------------- */

static void dtl_validate_record(dtl_validate_report *rep,
                                uint16_t section_index, size_t record_in_sec,
                                const dtl_record *rec)
{
    switch (rec->tag) {
    case DTL_REC_HEARTBEAT:
        if (rec->u.heartbeat.seq == 0)
            dtl_validate_add(rep, DTL_VALIDATE_WARNING, section_index,
                             record_in_sec, "heartbeat with seq 0");
        break;
    case DTL_REC_SENSOR:
        if (rec->u.sensor.count == 0)
            dtl_validate_add(rep, DTL_VALIDATE_INFO, section_index,
                             record_in_sec, "sensor record with no samples");
        break;
    case DTL_REC_EVENT:
        if (rec->u.event.payload_len == 0)
            dtl_validate_add(rep, DTL_VALIDATE_WARNING, section_index,
                             record_in_sec, "event 0x%04x with empty payload",
                             rec->u.event.code);
        break;
    case DTL_REC_DIAG:
        if (rec->u.diag.blob_len == 0 && !rec->u.diag.redacted)
            dtl_validate_add(rep, DTL_VALIDATE_WARNING, section_index,
                             record_in_sec,
                             "diag subsystem %u with empty blob",
                             rec->u.diag.subsystem);
        break;
    case DTL_REC_GEO:
        if (rec->u.geo.lat_e7 > 900000000 || rec->u.geo.lat_e7 < -900000000)
            dtl_validate_add(rep, DTL_VALIDATE_ERROR, section_index,
                             record_in_sec, "latitude %d out of range",
                             rec->u.geo.lat_e7);
        if (rec->u.geo.lon_e7 > 1800000000 || rec->u.geo.lon_e7 < -1800000000)
            dtl_validate_add(rep, DTL_VALIDATE_ERROR, section_index,
                             record_in_sec, "longitude %d out of range",
                             rec->u.geo.lon_e7);
        break;
    case DTL_REC_BATTERY:
        if (rec->u.battery.pct > 100)
            dtl_validate_add(rep, DTL_VALIDATE_ERROR, section_index,
                             record_in_sec, "battery pct %u over 100",
                             rec->u.battery.pct);
        break;
    case DTL_REC_NET:
        if (rec->u.net.rx_pkts == 0 && rec->u.net.rx_bytes != 0)
            dtl_validate_add(rep, DTL_VALIDATE_WARNING, section_index,
                             record_in_sec,
                             "rx_bytes nonzero with zero rx_pkts");
        if (rec->u.net.tx_pkts == 0 && rec->u.net.tx_bytes != 0)
            dtl_validate_add(rep, DTL_VALIDATE_WARNING, section_index,
                             record_in_sec,
                             "tx_bytes nonzero with zero tx_pkts");
        break;
    case DTL_REC_LOG:
        if (rec->u.log.severity > 7)
            dtl_validate_add(rep, DTL_VALIDATE_WARNING, section_index,
                             record_in_sec,
                             "log severity %u above syslog range",
                             rec->u.log.severity);
        if (rec->u.log.msg_len == 0)
            dtl_validate_add(rep, DTL_VALIDATE_INFO, section_index,
                             record_in_sec, "empty log message");
        break;
    case DTL_REC_CONFIG: {
        uint8_t i;
        for (i = 0; i < rec->u.config.pair_count; i++) {
            if (rec->u.config.pairs[i].key[0] == '\0')
                dtl_validate_add(rep, DTL_VALIDATE_ERROR, section_index,
                                 record_in_sec, "config pair %u has empty key",
                                 i);
        }
        break;
    }
    case DTL_REC_KEYREF:
        if (rec->u.keyref.slot_id == 0)
            dtl_validate_add(rep, DTL_VALIDATE_WARNING, section_index,
                             record_in_sec,
                             "keyref references reserved slot 0");
        break;
    case DTL_REC_FIRMWARE:
        if (rec->u.firmware.major == 0 && rec->u.firmware.minor == 0 &&
            rec->u.firmware.patch == 0)
            dtl_validate_add(rep, DTL_VALIDATE_WARNING, section_index,
                             record_in_sec, "firmware version 0.0.0");
        break;
    default:
        dtl_validate_add(rep, DTL_VALIDATE_ERROR, section_index,
                         record_in_sec, "unknown record tag 0x%02x",
                         rec->tag);
        break;
    }
}

/* ---- walk plumbing -------------------------------------------------------- */

typedef struct dtl_validate_ctx {
    dtl_validate_report *rep;
} dtl_validate_ctx;

static dtl_err dtl_validate_on_record(const dtl_walk_event *ev, void *user)
{
    dtl_validate_ctx *ctx = user;

    ctx->rep->records_checked++;
    dtl_validate_record(ctx->rep, ev->section_index, ev->record_in_sec,
                        ev->rec);
    return DTL_OK;
}

static void dtl_validate_on_error(const dtl_walk_error *we, void *user)
{
    dtl_validate_ctx *ctx = user;

    dtl_validate_add(ctx->rep, DTL_VALIDATE_ERROR, we->section_index,
                     we->record_in_sec, "decode/parse failure: %s",
                     dtl_strerror(we->rc));
}

static void dtl_validate_setup(dtl_validate_report *report,
                               struct dtl_arena *a,
                               dtl_validate_ctx *ctx, dtl_walk *w)
{
    memset(report, 0, sizeof(*report));
    report->a = a;
    ctx->rep = report;

    w->on_record = dtl_validate_on_record;
    w->on_error = dtl_validate_on_error;
    w->user = ctx;
    w->max_decode = 0;
}

static dtl_err dtl_validate_finish(dtl_validate_report *report, dtl_err rc)
{
    if (rc != DTL_OK)
        dtl_validate_add(report, DTL_VALIDATE_ERROR, 0, 0,
                         "container rejected: %s", dtl_strerror(rc));
    /* the report itself is the result, even for a rejected container */
    return DTL_OK;
}

dtl_err dtl_validate_file(const char *path, size_t max_file,
                          struct dtl_arena *a,
                          dtl_validate_report *report)
{
    dtl_validate_ctx ctx;
    dtl_walk w;

    if (report == NULL || a == NULL)
        return DTL_ERR_INVAL;

    dtl_validate_setup(report, a, &ctx, &w);
    return dtl_validate_finish(report, dtl_walk_file(path, max_file, &w));
}

dtl_err dtl_validate_memory(const uint8_t *data, size_t len,
                            struct dtl_arena *a,
                            dtl_validate_report *report)
{
    dtl_validate_ctx ctx;
    dtl_walk w;

    if (report == NULL || a == NULL)
        return DTL_ERR_INVAL;

    dtl_validate_setup(report, a, &ctx, &w);
    return dtl_validate_finish(report, dtl_walk_memory(data, len, a, &w));
}

static const char *dtl_validate_sev_name(dtl_validate_severity sev)
{
    switch (sev) {
    case DTL_VALIDATE_INFO:    return "info";
    case DTL_VALIDATE_WARNING: return "warning";
    case DTL_VALIDATE_ERROR:   return "error";
    default:                   return "?";
    }
}

void dtl_validate_print(const dtl_validate_report *report, FILE *out)
{
    size_t i;

    for (i = 0; i < report->issue_count; i++) {
        const dtl_issue *is = &report->issues[i];
        fprintf(out, "%-7s section=%u record=%llu %s\n",
                dtl_validate_sev_name(is->severity), is->section_index,
                (unsigned long long)is->record_in_sec, is->message);
    }
    fprintf(out, "validate: records=%llu errors=%llu warnings=%llu -> %s\n",
            (unsigned long long)report->records_checked,
            (unsigned long long)report->error_count,
            (unsigned long long)report->warning_count,
            report->error_count ? "FAIL" : "OK");
}
