#include "report/stats.h"

#include <string.h>

#include "report/walk.h"

static void dtl_num_add(dtl_numeric_stat *ns, double v)
{
    if (ns->count == 0) {
        ns->min = v;
        ns->max = v;
    } else {
        if (v < ns->min)
            ns->min = v;
        if (v > ns->max)
            ns->max = v;
    }
    ns->sum += v;
    ns->count++;
}

static double dtl_num_avg(const dtl_numeric_stat *ns)
{
    return ns->count ? ns->sum / (double)ns->count : 0.0;
}

void dtl_stats_init(dtl_stats *st)
{
    memset(st, 0, sizeof(*st));
}

static dtl_err dtl_stats_on_record(const dtl_walk_event *ev, void *user)
{
    dtl_stats *st = user;
    const dtl_record *rec = ev->rec;
    uint8_t i;

    st->total_records++;
    st->tag_counts[rec->tag]++;

    switch (rec->tag) {
    case DTL_REC_HEARTBEAT:
        dtl_num_add(&st->hb_uptime_s, (double)rec->u.heartbeat.uptime_s);
        dtl_num_add(&st->hb_seq, (double)rec->u.heartbeat.seq);
        break;
    case DTL_REC_SENSOR:
        dtl_num_add(&st->sensor_samples, (double)rec->u.sensor.count);
        for (i = 0; i < rec->u.sensor.count; i++)
            dtl_num_add(&st->sensor_value, (double)rec->u.sensor.samples[i]);
        break;
    case DTL_REC_EVENT:
        dtl_num_add(&st->event_code, (double)rec->u.event.code);
        dtl_num_add(&st->event_payload_len, (double)rec->u.event.payload_len);
        break;
    case DTL_REC_DIAG:
        dtl_num_add(&st->diag_blob_len, (double)rec->u.diag.blob_len);
        if (rec->u.diag.redacted)
            st->diag_redacted++;
        break;
    case DTL_REC_GEO:
        dtl_num_add(&st->geo_lat_e7, (double)rec->u.geo.lat_e7);
        dtl_num_add(&st->geo_lon_e7, (double)rec->u.geo.lon_e7);
        dtl_num_add(&st->geo_alt_mm, (double)rec->u.geo.alt_mm);
        break;
    case DTL_REC_BATTERY:
        dtl_num_add(&st->battery_pct, (double)rec->u.battery.pct);
        dtl_num_add(&st->battery_cycles, (double)rec->u.battery.cycles);
        break;
    case DTL_REC_NET:
        dtl_num_add(&st->net_rx_bytes, (double)rec->u.net.rx_bytes);
        dtl_num_add(&st->net_tx_bytes, (double)rec->u.net.tx_bytes);
        dtl_num_add(&st->net_rx_pkts, (double)rec->u.net.rx_pkts);
        dtl_num_add(&st->net_tx_pkts, (double)rec->u.net.tx_pkts);
        break;
    case DTL_REC_LOG:
        st->log_severity[rec->u.log.severity]++;
        break;
    case DTL_REC_CONFIG:
        dtl_num_add(&st->config_pairs, (double)rec->u.config.pair_count);
        break;
    case DTL_REC_KEYREF:
        if (rec->u.keyref.redacted)
            st->keyref_redacted++;
        break;
    case DTL_REC_FIRMWARE:
        break; /* version fields are categorical, not numeric */
    default:
        break;
    }
    return DTL_OK;
}

static void dtl_stats_on_error(const dtl_walk_error *we, void *user)
{
    dtl_stats *st = user;
    (void)we;
    st->parse_errors++;
}

dtl_err dtl_stats_collect_file(const char *path, size_t max_file,
                               dtl_stats *st)
{
    dtl_walk w;

    if (st == NULL)
        return DTL_ERR_INVAL;

    w.on_record = dtl_stats_on_record;
    w.on_error = dtl_stats_on_error;
    w.user = st;
    w.max_decode = 0;
    return dtl_walk_file(path, max_file, &w);
}

static void dtl_stats_print_num(FILE *out, const char *name,
                                const dtl_numeric_stat *ns)
{
    if (ns->count == 0)
        return;
    fprintf(out, "  %-22s n=%-6llu min=%-14.3f max=%-14.3f avg=%.3f\n",
            name,
            (unsigned long long)ns->count,
            ns->min, ns->max, dtl_num_avg(ns));
}

void dtl_stats_print(const dtl_stats *st, FILE *out)
{
    int tag;

    fprintf(out, "records: %llu\n", (unsigned long long)st->total_records);
    if (st->parse_errors)
        fprintf(out, "parse-errors: %llu\n",
                (unsigned long long)st->parse_errors);

    fprintf(out, "by-type:\n");
    for (tag = 0; tag < 256; tag++) {
        if (st->tag_counts[tag])
            fprintf(out, "  %-10s %llu\n", dtl_walk_tag_name((uint8_t)tag),
                    (unsigned long long)st->tag_counts[tag]);
    }

    fprintf(out, "numeric:\n");
    dtl_stats_print_num(out, "hb.uptime_s", &st->hb_uptime_s);
    dtl_stats_print_num(out, "hb.seq", &st->hb_seq);
    dtl_stats_print_num(out, "battery.pct", &st->battery_pct);
    dtl_stats_print_num(out, "battery.cycles", &st->battery_cycles);
    dtl_stats_print_num(out, "geo.lat_e7", &st->geo_lat_e7);
    dtl_stats_print_num(out, "geo.lon_e7", &st->geo_lon_e7);
    dtl_stats_print_num(out, "geo.alt_mm", &st->geo_alt_mm);
    dtl_stats_print_num(out, "net.rx_bytes", &st->net_rx_bytes);
    dtl_stats_print_num(out, "net.tx_bytes", &st->net_tx_bytes);
    dtl_stats_print_num(out, "net.rx_pkts", &st->net_rx_pkts);
    dtl_stats_print_num(out, "net.tx_pkts", &st->net_tx_pkts);
    dtl_stats_print_num(out, "sensor.samples", &st->sensor_samples);
    dtl_stats_print_num(out, "sensor.value", &st->sensor_value);
    dtl_stats_print_num(out, "event.code", &st->event_code);
    dtl_stats_print_num(out, "event.payload_len", &st->event_payload_len);
    dtl_stats_print_num(out, "diag.blob_len", &st->diag_blob_len);
    dtl_stats_print_num(out, "config.pairs", &st->config_pairs);

    {
        int printed = 0;
        int sev;
        for (sev = 0; sev < 256; sev++) {
            if (st->log_severity[sev]) {
                if (!printed) {
                    fprintf(out, "log-severity:\n");
                    printed = 1;
                }
                fprintf(out, "  %-3u %llu\n", sev,
                        (unsigned long long)st->log_severity[sev]);
            }
        }
    }

    if (st->keyref_redacted)
        fprintf(out, "keyref-redacted: %llu\n",
                (unsigned long long)st->keyref_redacted);
    if (st->diag_redacted)
        fprintf(out, "diag-redacted: %llu\n",
                (unsigned long long)st->diag_redacted);
}
