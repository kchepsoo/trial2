#include "report/topk.h"

#include <stdio.h>
#include <string.h>

#include "core/arena.h"
#include "report/walk.h"

/* ---- rankable fields -------------------------------------------------------- */

typedef double (*dtl_topk_extract_fn)(const dtl_record *rec);

typedef struct dtl_topk_field {
    const char         *name;
    uint8_t             tag;
    dtl_topk_extract_fn extract;
} dtl_topk_field;

static double dtl_topk_hb_uptime(const dtl_record *r)
{ return (double)r->u.heartbeat.uptime_s; }
static double dtl_topk_hb_seq(const dtl_record *r)
{ return (double)r->u.heartbeat.seq; }
static double dtl_topk_bat_pct(const dtl_record *r)
{ return (double)r->u.battery.pct; }
static double dtl_topk_bat_temp(const dtl_record *r)
{ return (double)r->u.battery.temp_c_e1; }
static double dtl_topk_bat_cycles(const dtl_record *r)
{ return (double)r->u.battery.cycles; }
static double dtl_topk_geo_lat(const dtl_record *r)
{ return (double)r->u.geo.lat_e7; }
static double dtl_topk_geo_lon(const dtl_record *r)
{ return (double)r->u.geo.lon_e7; }
static double dtl_topk_geo_alt(const dtl_record *r)
{ return (double)r->u.geo.alt_mm; }
static double dtl_topk_net_rxb(const dtl_record *r)
{ return (double)r->u.net.rx_bytes; }
static double dtl_topk_net_txb(const dtl_record *r)
{ return (double)r->u.net.tx_bytes; }
static double dtl_topk_net_rxp(const dtl_record *r)
{ return (double)r->u.net.rx_pkts; }
static double dtl_topk_net_txp(const dtl_record *r)
{ return (double)r->u.net.tx_pkts; }
static double dtl_topk_sensor_id(const dtl_record *r)
{ return (double)r->u.sensor.sensor_id; }
static double dtl_topk_sensor_count(const dtl_record *r)
{ return (double)r->u.sensor.count; }
static double dtl_topk_event_code(const dtl_record *r)
{ return (double)r->u.event.code; }
static double dtl_topk_event_plen(const dtl_record *r)
{ return (double)r->u.event.payload_len; }
static double dtl_topk_log_sev(const dtl_record *r)
{ return (double)r->u.log.severity; }
static double dtl_topk_config_pairs(const dtl_record *r)
{ return (double)r->u.config.pair_count; }
static double dtl_topk_diag_blob(const dtl_record *r)
{ return (double)r->u.diag.blob_len; }

static const dtl_topk_field kFields[] = {
    { "heartbeat.uptime_s", DTL_REC_HEARTBEAT, dtl_topk_hb_uptime     },
    { "heartbeat.seq",      DTL_REC_HEARTBEAT, dtl_topk_hb_seq        },
    { "battery.pct",        DTL_REC_BATTERY,   dtl_topk_bat_pct       },
    { "battery.temp_c_e1",  DTL_REC_BATTERY,   dtl_topk_bat_temp      },
    { "battery.cycles",     DTL_REC_BATTERY,   dtl_topk_bat_cycles    },
    { "geo.lat_e7",         DTL_REC_GEO,       dtl_topk_geo_lat       },
    { "geo.lon_e7",         DTL_REC_GEO,       dtl_topk_geo_lon       },
    { "geo.alt_mm",         DTL_REC_GEO,       dtl_topk_geo_alt       },
    { "net.rx_bytes",       DTL_REC_NET,       dtl_topk_net_rxb       },
    { "net.tx_bytes",       DTL_REC_NET,       dtl_topk_net_txb       },
    { "net.rx_pkts",        DTL_REC_NET,       dtl_topk_net_rxp       },
    { "net.tx_pkts",        DTL_REC_NET,       dtl_topk_net_txp       },
    { "sensor.sensor_id",   DTL_REC_SENSOR,    dtl_topk_sensor_id     },
    { "sensor.count",       DTL_REC_SENSOR,    dtl_topk_sensor_count  },
    { "event.code",         DTL_REC_EVENT,     dtl_topk_event_code    },
    { "event.payload_len",  DTL_REC_EVENT,     dtl_topk_event_plen    },
    { "log.severity",       DTL_REC_LOG,       dtl_topk_log_sev       },
    { "config.pair_count",  DTL_REC_CONFIG,    dtl_topk_config_pairs  },
    { "diag.blob_len",      DTL_REC_DIAG,      dtl_topk_diag_blob     },
};

#define DTL_TOPK_FIELD_COUNT (sizeof(kFields) / sizeof(kFields[0]))

static const dtl_topk_field *dtl_topk_lookup(const char *name)
{
    size_t i;
    for (i = 0; i < DTL_TOPK_FIELD_COUNT; i++) {
        if (strcmp(name, kFields[i].name) == 0)
            return &kFields[i];
    }
    return NULL;
}

int dtl_topk_field_exists(const char *name)
{
    return dtl_topk_lookup(name) != NULL;
}

void dtl_topk_list_fields(FILE *out)
{
    size_t i;
    fprintf(out, "rankable fields:\n");
    for (i = 0; i < DTL_TOPK_FIELD_COUNT; i++)
        fprintf(out, "  %s\n", kFields[i].name);
}

/* ---- collection --------------------------------------------------------------- */

typedef struct dtl_topk_entry {
    double value;
    size_t record_index;
} dtl_topk_entry;

typedef struct dtl_topk_ctx {
    const dtl_topk_field *field;
    dtl_arena            *a;
    dtl_topk_entry       *entries;
    size_t                count;
    size_t                cap;
} dtl_topk_ctx;

static dtl_err dtl_topk_on_record(const dtl_walk_event *ev, void *user)
{
    dtl_topk_ctx *ctx = user;

    if (ev->rec->tag != ctx->field->tag)
        return DTL_OK;

    if (ctx->count == ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 64;
        dtl_topk_entry *grown =
            dtl_arena_alloc(ctx->a, new_cap * sizeof(*grown));
        if (grown == NULL)
            return DTL_ERR_OOM;
        if (ctx->count != 0)
            memcpy(grown, ctx->entries, ctx->count * sizeof(*grown));
        ctx->entries = grown;
        ctx->cap = new_cap;
    }
    ctx->entries[ctx->count].value = ctx->field->extract(ev->rec);
    ctx->entries[ctx->count].record_index = ev->record_index;
    ctx->count++;
    return DTL_OK;
}

/* Stable descending insertion sort: fine for top-N reporting sizes and keeps
 * equal values in wire order, which the smoke test depends on. */
static void dtl_topk_sort(dtl_topk_entry *e, size_t n)
{
    size_t i;
    for (i = 1; i < n; i++) {
        dtl_topk_entry key = e[i];
        size_t j = i;
        while (j > 0 && e[j - 1].value < key.value) {
            e[j] = e[j - 1];
            j--;
        }
        e[j] = key;
    }
}

dtl_err dtl_topk_file(const char *path, size_t max_file, const char *field,
                      size_t n, FILE *out)
{
    const dtl_topk_field *fld = dtl_topk_lookup(field);
    dtl_arena a;
    dtl_topk_ctx ctx;
    dtl_walk w;
    dtl_err rc;
    size_t i, shown;

    if (fld == NULL)
        return DTL_ERR_INVAL;

    dtl_arena_init(&a, 256 * 1024);
    memset(&ctx, 0, sizeof(ctx));
    ctx.field = fld;
    ctx.a = &a;

    w.on_record = dtl_topk_on_record;
    w.on_error = NULL;
    w.user = &ctx;
    w.max_decode = 0;

    rc = dtl_walk_file(path, max_file, &w);
    if (rc != DTL_OK) {
        dtl_arena_free(&a);
        return rc;
    }

    dtl_topk_sort(ctx.entries, ctx.count);

    shown = (n == 0 || n > ctx.count) ? ctx.count : n;
    fprintf(out, "top-%llu by %s (%llu candidates):\n",
            (unsigned long long)shown, fld->name,
            (unsigned long long)ctx.count);
    for (i = 0; i < shown; i++) {
        fprintf(out, "  %4llu  record=%-8llu value=%.3f\n",
                (unsigned long long)(i + 1),
                (unsigned long long)ctx.entries[i].record_index,
                ctx.entries[i].value);
    }

    dtl_arena_free(&a);
    return DTL_OK;
}
