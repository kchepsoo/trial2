#ifndef DTL_REPORT_STATS_H
#define DTL_REPORT_STATS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "core/err.h"

/*
 * report/stats -- aggregate statistics over a DTL container's records.
 *
 * dtl_stats_collect walks a container file and accumulates per-tag counts
 * plus a set of numeric aggregates over the fields of the fixed-layout
 * records (heartbeat uptime/sequence, battery level, geo extremes, network
 * counters) and the variable-length ones (log severity histogram, sensor
 * sample statistics). The result is printed with dtl_stats_print.
 */

typedef struct dtl_numeric_stat {
    uint64_t count;
    double   min;
    double   max;
    double   sum;
} dtl_numeric_stat;

typedef struct dtl_stats {
    uint64_t total_records;
    uint64_t total_sections_seen;
    uint64_t tag_counts[256];
    uint64_t parse_errors;

    dtl_numeric_stat hb_uptime_s;
    dtl_numeric_stat hb_seq;
    dtl_numeric_stat battery_pct;
    dtl_numeric_stat battery_cycles;
    dtl_numeric_stat geo_lat_e7;
    dtl_numeric_stat geo_lon_e7;
    dtl_numeric_stat geo_alt_mm;
    dtl_numeric_stat net_rx_bytes;
    dtl_numeric_stat net_tx_bytes;
    dtl_numeric_stat net_rx_pkts;
    dtl_numeric_stat net_tx_pkts;
    dtl_numeric_stat sensor_samples;    /* per-record sample count          */
    dtl_numeric_stat sensor_value;      /* individual sample values         */
    dtl_numeric_stat event_code;
    dtl_numeric_stat event_payload_len;
    dtl_numeric_stat diag_blob_len;
    dtl_numeric_stat config_pairs;

    uint64_t log_severity[256];
    uint64_t keyref_redacted;
    uint64_t diag_redacted;
} dtl_stats;

void dtl_stats_init(dtl_stats *st);

/*
 * dtl_stats_collect_file -- accumulate statistics for the container at path
 * (size-capped at max_file bytes) into st. May be called repeatedly to
 * combine several containers into one accumulator.
 */
dtl_err dtl_stats_collect_file(const char *path, size_t max_file,
                               dtl_stats *st);

/* dtl_stats_print -- human-readable report. */
void dtl_stats_print(const dtl_stats *st, FILE *out);

#endif /* DTL_REPORT_STATS_H */
