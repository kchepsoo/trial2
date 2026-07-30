#include "report/export.h"

#include <string.h>

#include "report/walk.h"

/* ---- shared emit helpers ------------------------------------------------ */

static void dtl_export_csv_string(FILE *out, const char *s, size_t n)
{
    size_t i;
    fputc('"', out);
    for (i = 0; i < n; i++) {
        char c = s[i];
        if (c == '"')
            fputc('"', out); /* CSV: double the quote */
        fputc(c, out);
    }
    fputc('"', out);
}

static void dtl_export_json_string(FILE *out, const char *s, size_t n)
{
    size_t i;
    fputc('"', out);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out);  break;
        case '\r': fputs("\\r", out);  break;
        case '\t': fputs("\\t", out);  break;
        default:
            if (c < 0x20)
                fprintf(out, "\\u%04x", c);
            else
                fputc(c, out);
        }
    }
    fputc('"', out);
}

static void dtl_export_hex(FILE *out, const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        fprintf(out, "%02x", p[i]);
}

/* ---- CSV ---------------------------------------------------------------- */

static void dtl_export_csv_header(FILE *out)
{
    fputs("index,tag,f0,f1,f2,f3,f4,f5\n", out);
}

static void dtl_export_csv_record(FILE *out, const dtl_record *rec,
                                  size_t index)
{
    fprintf(out, "%llu,%s", (unsigned long long)index,
            dtl_walk_tag_name(rec->tag));

    switch (rec->tag) {
    case DTL_REC_HEARTBEAT:
        fprintf(out, ",%u,%u,,,,", rec->u.heartbeat.uptime_s,
                rec->u.heartbeat.seq);
        break;
    case DTL_REC_SENSOR: {
        uint8_t i;
        fprintf(out, ",%u,%u", rec->u.sensor.sensor_id, rec->u.sensor.count);
        for (i = 0; i < rec->u.sensor.count && i < 4; i++)
            fprintf(out, ",%.6g", (double)rec->u.sensor.samples[i]);
        break;
    }
    case DTL_REC_EVENT:
        fprintf(out, ",%u,%u,", rec->u.event.code, rec->u.event.payload_len);
        dtl_export_hex(out, rec->u.event.payload, rec->u.event.payload_len);
        fputs(",,", out);
        break;
    case DTL_REC_DIAG:
        fprintf(out, ",%u,%u,%u,", rec->u.diag.subsystem,
                rec->u.diag.blob_len, rec->u.diag.redacted);
        dtl_export_hex(out, rec->u.diag.blob,
                       rec->u.diag.redacted ? 0 : rec->u.diag.blob_len);
        fputs(",,", out);
        break;
    case DTL_REC_GEO:
        fprintf(out, ",%d,%d,%d,,,", rec->u.geo.lat_e7, rec->u.geo.lon_e7,
                rec->u.geo.alt_mm);
        break;
    case DTL_REC_BATTERY:
        fprintf(out, ",%u,%d,%u,,,", rec->u.battery.pct,
                rec->u.battery.temp_c_e1, rec->u.battery.cycles);
        break;
    case DTL_REC_NET:
        fprintf(out, ",%u,%u,%u,%u,%u,", rec->u.net.iface_id,
                rec->u.net.rx_bytes, rec->u.net.tx_bytes,
                rec->u.net.rx_pkts, rec->u.net.tx_pkts);
        break;
    case DTL_REC_LOG:
        fprintf(out, ",%u,", rec->u.log.severity);
        dtl_export_csv_string(out, rec->u.log.msg, rec->u.log.msg_len);
        fputs(",,,", out);
        break;
    case DTL_REC_CONFIG: {
        uint8_t i;
        fprintf(out, ",%u", rec->u.config.pair_count);
        for (i = 0; i < rec->u.config.pair_count && i < 2; i++) {
            fputc(',', out);
            dtl_export_csv_string(out, rec->u.config.pairs[i].key,
                                  strlen(rec->u.config.pairs[i].key));
            fputc(',', out);
            dtl_export_csv_string(out, rec->u.config.pairs[i].value,
                                  strlen(rec->u.config.pairs[i].value));
        }
        break;
    }
    case DTL_REC_KEYREF:
        fprintf(out, ",%u,%u,", rec->u.keyref.slot_id,
                rec->u.keyref.redacted);
        dtl_export_csv_string(out, rec->u.keyref.label,
                              rec->u.keyref.redacted ? 0
                                                     : rec->u.keyref.label_len);
        fputs(",,,", out);
        break;
    case DTL_REC_FIRMWARE:
        fprintf(out, ",%u,%u,%u,", rec->u.firmware.major,
                rec->u.firmware.minor, rec->u.firmware.patch);
        dtl_export_hex(out, rec->u.firmware.hash, 8);
        fputs(",,", out);
        break;
    default:
        fputs(",,,,,,", out);
        break;
    }
    fputc('\n', out);
}

/* ---- JSON --------------------------------------------------------------- */

static void dtl_export_json_kv_tail(FILE *out, const dtl_record *rec)
{
    switch (rec->tag) {
    case DTL_REC_HEARTBEAT:
        fprintf(out, ",\"uptime_s\":%u,\"seq\":%u", rec->u.heartbeat.uptime_s,
                rec->u.heartbeat.seq);
        break;
    case DTL_REC_SENSOR: {
        uint8_t i;
        fprintf(out, ",\"sensor_id\":%u,\"samples\":[", rec->u.sensor.sensor_id);
        for (i = 0; i < rec->u.sensor.count; i++)
            fprintf(out, "%s%.9g", i ? "," : "",
                    (double)rec->u.sensor.samples[i]);
        fputc(']', out);
        break;
    }
    case DTL_REC_EVENT:
        fprintf(out, ",\"code\":%u,\"payload_hex\":\"", rec->u.event.code);
        dtl_export_hex(out, rec->u.event.payload, rec->u.event.payload_len);
        fputc('"', out);
        break;
    case DTL_REC_DIAG:
        fprintf(out, ",\"subsystem\":%u,\"redacted\":%s,\"blob_hex\":\"",
                rec->u.diag.subsystem,
                rec->u.diag.redacted ? "true" : "false");
        dtl_export_hex(out, rec->u.diag.blob,
                       rec->u.diag.redacted ? 0 : rec->u.diag.blob_len);
        fputc('"', out);
        break;
    case DTL_REC_GEO:
        fprintf(out, ",\"lat_e7\":%d,\"lon_e7\":%d,\"alt_mm\":%d",
                rec->u.geo.lat_e7, rec->u.geo.lon_e7, rec->u.geo.alt_mm);
        break;
    case DTL_REC_BATTERY:
        fprintf(out, ",\"pct\":%u,\"temp_c_e1\":%d,\"cycles\":%u",
                rec->u.battery.pct, rec->u.battery.temp_c_e1,
                rec->u.battery.cycles);
        break;
    case DTL_REC_NET:
        fprintf(out, ",\"iface_id\":%u,\"rx_bytes\":%u,\"tx_bytes\":%u"
                     ",\"rx_pkts\":%u,\"tx_pkts\":%u",
                rec->u.net.iface_id, rec->u.net.rx_bytes,
                rec->u.net.tx_bytes, rec->u.net.rx_pkts, rec->u.net.tx_pkts);
        break;
    case DTL_REC_LOG:
        fprintf(out, ",\"severity\":%u,\"msg\":", rec->u.log.severity);
        dtl_export_json_string(out, rec->u.log.msg, rec->u.log.msg_len);
        break;
    case DTL_REC_CONFIG: {
        uint8_t i;
        fputs(",\"pairs\":{", out);
        for (i = 0; i < rec->u.config.pair_count; i++) {
            if (i)
                fputc(',', out);
            dtl_export_json_string(out, rec->u.config.pairs[i].key,
                                   strlen(rec->u.config.pairs[i].key));
            fputc(':', out);
            dtl_export_json_string(out, rec->u.config.pairs[i].value,
                                   strlen(rec->u.config.pairs[i].value));
        }
        fputc('}', out);
        break;
    }
    case DTL_REC_KEYREF:
        fprintf(out, ",\"slot_id\":%u,\"redacted\":%s,\"label\":",
                rec->u.keyref.slot_id,
                rec->u.keyref.redacted ? "true" : "false");
        dtl_export_json_string(out, rec->u.keyref.label,
                               rec->u.keyref.redacted ? 0
                                                      : rec->u.keyref.label_len);
        break;
    case DTL_REC_FIRMWARE:
        fprintf(out, ",\"version\":\"%u.%u.%u\",\"hash_hex\":\"",
                rec->u.firmware.major, rec->u.firmware.minor,
                rec->u.firmware.patch);
        dtl_export_hex(out, rec->u.firmware.hash, 8);
        fputc('"', out);
        break;
    default:
        break;
    }
}

static void dtl_export_json_record(FILE *out, const dtl_record *rec,
                                   size_t index, int first)
{
    fprintf(out, "%s\n  {\"index\":%llu,\"tag\":%u,\"type\":\"%s\"",
            first ? "" : ",", (unsigned long long)index, rec->tag,
            dtl_walk_tag_name(rec->tag));
    dtl_export_json_kv_tail(out, rec);
    fputc('}', out);
}

/* ---- public API ---------------------------------------------------------- */

void dtl_export_record(FILE *out, dtl_export_format fmt,
                       const dtl_record *rec, size_t index)
{
    if (fmt == DTL_EXPORT_JSON)
        dtl_export_json_record(out, rec, index, 1);
    else
        dtl_export_csv_record(out, rec, index);
}

typedef struct dtl_export_ctx {
    FILE             *out;
    dtl_export_format fmt;
    size_t            emitted;
} dtl_export_ctx;

static dtl_err dtl_export_on_record(const dtl_walk_event *ev, void *user)
{
    dtl_export_ctx *ctx = user;

    if (ctx->fmt == DTL_EXPORT_JSON)
        dtl_export_json_record(ctx->out, ev->rec, ev->record_index,
                               ctx->emitted == 0);
    else
        dtl_export_csv_record(ctx->out, ev->rec, ev->record_index);
    ctx->emitted++;
    return DTL_OK;
}

dtl_err dtl_export_file(const char *path, size_t max_file,
                        dtl_export_format fmt, FILE *out)
{
    dtl_export_ctx ctx;
    dtl_walk w;
    dtl_err rc;

    ctx.out = out;
    ctx.fmt = fmt;
    ctx.emitted = 0;

    w.on_record = dtl_export_on_record;
    w.on_error = NULL;
    w.user = &ctx;
    w.max_decode = 0;

    if (fmt == DTL_EXPORT_JSON)
        fputc('[', out);
    else
        dtl_export_csv_header(out);

    rc = dtl_walk_file(path, max_file, &w);

    if (fmt == DTL_EXPORT_JSON)
        fputs("\n]\n", out);
    return rc;
}

int dtl_export_parse_format(const char *name, dtl_export_format *out)
{
    if (strcmp(name, "csv") == 0) {
        *out = DTL_EXPORT_CSV;
        return 0;
    }
    if (strcmp(name, "json") == 0) {
        *out = DTL_EXPORT_JSON;
        return 0;
    }
    return -1;
}
