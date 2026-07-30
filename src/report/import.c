#include "report/import.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "codec/registry.h"
#include "core/arena.h"
#include "report/walk.h"
#include "records/record.h"
#include "writer/writer.h"

/* ---- CSV row tokenizer ---------------------------------------------------- */

#define DTL_IMPORT_MAX_FIELDS 8
#define DTL_IMPORT_FIELD_CAP  4096

typedef struct dtl_csv_field {
    char   text[DTL_IMPORT_FIELD_CAP];
    size_t len;
} dtl_csv_field;

typedef struct dtl_csv_row {
    dtl_csv_field f[DTL_IMPORT_MAX_FIELDS];
    size_t        count;
} dtl_csv_row;

/*
 * Parse one CSV line (without the trailing newline) into row. Handles
 * double-quoted fields with doubled-quote escapes. Returns DTL_OK, or
 * DTL_ERR_BADRECORD on unbalanced quotes or too many fields.
 */
static dtl_err dtl_csv_parse_row(const char *line, dtl_csv_row *row)
{
    const char *p = line;
    size_t fi = 0;

    memset(row, 0, sizeof(*row));

    if (*p == '\0')
        return DTL_ERR_TRUNCATED; /* empty line: caller skips */

    for (;;) {
        dtl_csv_field *fld;
        size_t n = 0;

        if (fi == DTL_IMPORT_MAX_FIELDS)
            return DTL_ERR_BADRECORD;
        fld = &row->f[fi];

        if (*p == '"') {
            p++;
            for (;;) {
                if (*p == '\0')
                    return DTL_ERR_BADRECORD; /* unbalanced quote */
                if (*p == '"') {
                    if (p[1] == '"') {
                        if (n + 1 >= DTL_IMPORT_FIELD_CAP)
                            return DTL_ERR_BADRECORD;
                        fld->text[n++] = '"';
                        p += 2;
                        continue;
                    }
                    p++; /* closing quote */
                    break;
                }
                if (n + 1 >= DTL_IMPORT_FIELD_CAP)
                    return DTL_ERR_BADRECORD;
                fld->text[n++] = *p++;
            }
            if (*p != ',' && *p != '\0')
                return DTL_ERR_BADRECORD;
        } else {
            while (*p != ',' && *p != '\0') {
                if (n + 1 >= DTL_IMPORT_FIELD_CAP)
                    return DTL_ERR_BADRECORD;
                fld->text[n++] = *p++;
            }
        }
        fld->text[n] = '\0';
        fld->len = n;
        fi++;

        if (*p == '\0')
            break;
        p++; /* consume the comma */
    }

    row->count = fi;
    return DTL_OK;
}

/* ---- scalar field parsers --------------------------------------------------- */

static int dtl_field_u32(const dtl_csv_field *f, uint32_t *out)
{
    char *end = NULL;
    unsigned long v = strtoul(f->text, &end, 10);
    if (end == f->text || *end != '\0' || v > 0xFFFFFFFFul)
        return -1;
    *out = (uint32_t)v;
    return 0;
}

static int dtl_field_i32(const dtl_csv_field *f, int32_t *out)
{
    char *end = NULL;
    long v = strtol(f->text, &end, 10);
    if (end == f->text || *end != '\0')
        return -1;
    *out = (int32_t)v;
    return 0;
}

static int dtl_field_float(const dtl_csv_field *f, float *out)
{
    char *end = NULL;
    float v = strtof(f->text, &end);
    if (end == f->text)
        return -1;
    *out = v;
    return 0;
}

static int dtl_field_hex(const dtl_csv_field *f, uint8_t *out, size_t out_cap,
                         size_t *out_len)
{
    size_t i;

    if (f->len % 2 != 0 || f->len / 2 > out_cap)
        return -1;
    for (i = 0; i < f->len / 2; i++) {
        int hi = f->text[2 * i];
        int lo = f->text[2 * i + 1];
        hi = hi >= '0' && hi <= '9' ? hi - '0'
           : hi >= 'a' && hi <= 'f' ? hi - 'a' + 10
           : hi >= 'A' && hi <= 'F' ? hi - 'A' + 10 : -1;
        lo = lo >= '0' && lo <= '9' ? lo - '0'
           : lo >= 'a' && lo <= 'f' ? lo - 'a' + 10
           : lo >= 'A' && lo <= 'F' ? lo - 'A' + 10 : -1;
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = f->len / 2;
    return 0;
}

static const char *dtl_field_dup(dtl_arena *a, const dtl_csv_field *f)
{
    char *p = dtl_arena_alloc(a, f->len + 1);
    if (p == NULL)
        return NULL;
    memcpy(p, f->text, f->len + 1);
    return p;
}

/* ---- tag lookup --------------------------------------------------------------- */

static int dtl_import_tag(const char *name, uint8_t *out)
{
    static const struct {
        const char *name;
        uint8_t     tag;
    } kTags[] = {
        { "HEARTBEAT", DTL_REC_HEARTBEAT },
        { "SENSOR",    DTL_REC_SENSOR    },
        { "EVENT",     DTL_REC_EVENT     },
        { "DIAG",      DTL_REC_DIAG      },
        { "GEO",       DTL_REC_GEO       },
        { "BATTERY",   DTL_REC_BATTERY   },
        { "NET",       DTL_REC_NET       },
        { "LOG",       DTL_REC_LOG       },
        { "CONFIG",    DTL_REC_CONFIG    },
        { "KEYREF",    DTL_REC_KEYREF    },
        { "FIRMWARE",  DTL_REC_FIRMWARE  },
    };
    size_t i;

    for (i = 0; i < sizeof(kTags) / sizeof(kTags[0]); i++) {
        if (strcmp(name, kTags[i].name) == 0) {
            *out = kTags[i].tag;
            return 0;
        }
    }
    return -1;
}

/* ---- row -> record -------------------------------------------------------------- */

static dtl_err dtl_import_row(dtl_arena *a, const dtl_csv_row *row,
                              dtl_record *rec)
{
    uint32_t u0, u1, u2, u3, u4;
    int32_t s0, s1, s2;

    if (row->count < 2)
        return DTL_ERR_BADRECORD;
    if (dtl_import_tag(row->f[1].text, &rec->tag) != 0)
        return DTL_ERR_BADRECORD;

#define DTL_U(ix, dst)                                                        \
    do {                                                                      \
        if (row->count <= (ix) || dtl_field_u32(&row->f[ix], &(dst)) != 0)    \
            return DTL_ERR_BADRECORD;                                         \
    } while (0)
#define DTL_I(ix, dst)                                                        \
    do {                                                                      \
        if (row->count <= (ix) || dtl_field_i32(&row->f[ix], &(dst)) != 0)    \
            return DTL_ERR_BADRECORD;                                         \
    } while (0)

    switch (rec->tag) {
    case DTL_REC_HEARTBEAT:
        DTL_U(2, u0);
        DTL_U(3, u1);
        rec->u.heartbeat.uptime_s = u0;
        rec->u.heartbeat.seq = u1;
        break;
    case DTL_REC_GEO:
        DTL_I(2, s0);
        DTL_I(3, s1);
        DTL_I(4, s2);
        rec->u.geo.lat_e7 = s0;
        rec->u.geo.lon_e7 = s1;
        rec->u.geo.alt_mm = s2;
        break;
    case DTL_REC_BATTERY:
        DTL_U(2, u0);
        DTL_I(3, s0);
        DTL_U(4, u1);
        if (u0 > 255 || s0 < -32768 || s0 > 32767)
            return DTL_ERR_BADRECORD;
        rec->u.battery.pct = (uint8_t)u0;
        rec->u.battery.temp_c_e1 = (int16_t)s0;
        rec->u.battery.cycles = u1;
        break;
    case DTL_REC_NET:
        DTL_U(2, u0);
        DTL_U(3, u1);
        DTL_U(4, u2);
        DTL_U(5, u3);
        DTL_U(6, u4);
        if (u0 > 255)
            return DTL_ERR_BADRECORD;
        rec->u.net.iface_id = (uint8_t)u0;
        rec->u.net.rx_bytes = u1;
        rec->u.net.tx_bytes = u2;
        rec->u.net.rx_pkts = u3;
        rec->u.net.tx_pkts = u4;
        break;
    case DTL_REC_FIRMWARE: {
        size_t n = 0;
        DTL_U(2, u0);
        DTL_U(3, u1);
        DTL_U(4, u2);
        if (u0 > 0xFFFF || u1 > 0xFFFF || u2 > 0xFFFF)
            return DTL_ERR_BADRECORD;
        if (row->count <= 5 ||
            dtl_field_hex(&row->f[5], rec->u.firmware.hash, 8, &n) != 0 ||
            n != 8)
            return DTL_ERR_BADRECORD;
        rec->u.firmware.major = (uint16_t)u0;
        rec->u.firmware.minor = (uint16_t)u1;
        rec->u.firmware.patch = (uint16_t)u2;
        break;
    }
    case DTL_REC_SENSOR: {
        uint8_t cnt = 0;
        size_t fi;
        float *samples = dtl_arena_alloc(a, 4 * sizeof(float));
        if (samples == NULL)
            return DTL_ERR_OOM;
        DTL_U(2, u0);
        DTL_U(3, u1);
        if (u0 > 0xFFFF || u1 > 4)
            return DTL_ERR_BADRECORD;
        for (fi = 4; fi < row->count && cnt < u1; fi++) {
            if (row->f[fi].len == 0)
                continue;
            if (dtl_field_float(&row->f[fi], &samples[cnt]) != 0)
                return DTL_ERR_BADRECORD;
            cnt++;
        }
        if (cnt != u1)
            return DTL_ERR_BADRECORD;
        rec->u.sensor.sensor_id = (uint16_t)u0;
        rec->u.sensor.count = cnt;
        rec->u.sensor.samples = cnt ? samples : NULL;
        break;
    }
    case DTL_REC_EVENT: {
        uint8_t *payload;
        size_t n = 0;
        DTL_U(2, u0);
        DTL_U(3, u1);
        if (u0 > 0xFFFF || u1 > 0xFFFF)
            return DTL_ERR_BADRECORD;
        payload = dtl_arena_alloc(a, u1 ? u1 : 1);
        if (payload == NULL)
            return DTL_ERR_OOM;
        if (row->count > 4 && row->f[4].len != 0) {
            if (dtl_field_hex(&row->f[4], payload, u1, &n) != 0 || n != u1)
                return DTL_ERR_BADRECORD;
        } else if (u1 != 0) {
            return DTL_ERR_BADRECORD;
        }
        rec->u.event.code = (uint16_t)u0;
        rec->u.event.payload_len = (uint16_t)u1;
        rec->u.event.payload = u1 ? payload : NULL;
        break;
    }
    case DTL_REC_LOG: {
        const char *msg;
        DTL_U(2, u0);
        if (u0 > 255 || row->count <= 3)
            return DTL_ERR_BADRECORD;
        msg = dtl_field_dup(a, &row->f[3]);
        if (msg == NULL)
            return DTL_ERR_OOM;
        if (row->f[3].len > 0xFFFF)
            return DTL_ERR_BADRECORD;
        rec->u.log.severity = (uint8_t)u0;
        rec->u.log.msg = msg;
        rec->u.log.msg_len = (uint16_t)row->f[3].len;
        break;
    }
    case DTL_REC_CONFIG: {
        dtl_config_pair *pairs;
        uint8_t cnt = 0;
        size_t fi;
        DTL_U(2, u0);
        if (u0 > 2)
            return DTL_ERR_BADRECORD; /* export layout carries at most 2 */
        pairs = dtl_arena_alloc(a, (u0 ? u0 : 1) * sizeof(*pairs));
        if (pairs == NULL)
            return DTL_ERR_OOM;
        fi = 3;
        while (cnt < u0) {
            if (fi + 1 >= row->count)
                return DTL_ERR_BADRECORD;
            pairs[cnt].key = dtl_field_dup(a, &row->f[fi]);
            pairs[cnt].value = dtl_field_dup(a, &row->f[fi + 1]);
            if (pairs[cnt].key == NULL || pairs[cnt].value == NULL)
                return DTL_ERR_OOM;
            cnt++;
            fi += 2;
        }
        rec->u.config.pair_count = cnt;
        rec->u.config.pairs = cnt ? pairs : NULL;
        break;
    }
    case DTL_REC_KEYREF: {
        const char *label;
        DTL_U(2, u0);
        if (u0 > 255 || row->count <= 4)
            return DTL_ERR_BADRECORD;
        label = dtl_field_dup(a, &row->f[4]);
        if (label == NULL)
            return DTL_ERR_OOM;
        if (row->f[4].len > 255)
            return DTL_ERR_BADRECORD;
        rec->u.keyref.slot_id = (uint8_t)u0;
        rec->u.keyref.redacted = 0;
        rec->u.keyref.label = label;
        rec->u.keyref.label_len = (uint8_t)row->f[4].len;
        break;
    }
    case DTL_REC_DIAG: {
        uint8_t *blob;
        size_t n = 0;
        DTL_U(2, u0);
        DTL_U(3, u1);
        if (u0 > 0xFFFF || u1 > 0xFFFF)
            return DTL_ERR_BADRECORD;
        /* Size the blob to the hex payload actually present; the declared
         * length is carried through to the record for the wire form. */
        if (row->count > 5 && row->f[5].len != 0) {
            size_t have = row->f[5].len / 2;
            blob = dtl_arena_alloc(a, have ? have : 1);
            if (blob == NULL)
                return DTL_ERR_OOM;
            if (dtl_field_hex(&row->f[5], blob, have, &n) != 0)
                return DTL_ERR_BADRECORD;
        } else if (u1 != 0) {
            return DTL_ERR_BADRECORD;
        } else {
            blob = dtl_arena_alloc(a, 1);
            if (blob == NULL)
                return DTL_ERR_OOM;
        }
        rec->u.diag.subsystem = (uint16_t)u0;
        rec->u.diag.blob_len = (uint16_t)u1;
        rec->u.diag.blob = u1 ? blob : NULL;
        rec->u.diag.redacted = 0;
        break;
    }
    default:
        return DTL_ERR_BADRECORD;
    }
#undef DTL_U
#undef DTL_I
    return DTL_OK;
}

/* ---- top level -------------------------------------------------------------------- */

/*
 * dtl_import_csv_memory -- parse CSV text held in memory and emit the
 * constructed container into the caller's arena. All record payloads and the
 * output bytes are allocated from a and stay valid until it is freed.
 */
dtl_err dtl_import_csv_memory(const uint8_t *data, size_t len, dtl_arena *a,
                              uint8_t **out_bytes, size_t *out_len,
                              size_t *out_records)
{
    dtl_writer w;
    dtl_err rc = DTL_OK;
    size_t pos = 0;
    size_t line_no = 0;
    size_t imported = 0;
    int section_open = 0;

    if (data == NULL || a == NULL || out_bytes == NULL || out_len == NULL)
        return DTL_ERR_INVAL;

    dtl_writer_init(&w, a);

    while (pos < len) {
        char line[8192];
        size_t L = 0;
        dtl_csv_row row;
        dtl_record rec;

        /* copy one line, bounded; an over-long line is a format error */
        while (pos < len && data[pos] != '\n') {
            if (L + 1 >= sizeof(line))
                return DTL_ERR_BADRECORD;
            line[L++] = (char)data[pos++];
        }
        if (pos < len)
            pos++; /* consume the newline */
        while (L != 0 && line[L - 1] == '\r')
            L--;
        line[L] = '\0';

        line_no++;
        if (L == 0)
            continue;
        if (line_no == 1 && strncmp(line, "index,tag,", 10) == 0)
            continue; /* header row */

        rc = dtl_csv_parse_row(line, &row);
        if (rc == DTL_ERR_TRUNCATED)
            continue;
        if (rc != DTL_OK)
            return rc;

        memset(&rec, 0, sizeof(rec));
        rc = dtl_import_row(a, &row, &rec);
        if (rc != DTL_OK)
            return rc;

        if (!section_open) {
            if (dtl_writer_begin_section(&w, 1, DTL_CODEC_STORE) < 0)
                return DTL_ERR_OOM;
            section_open = 1;
        }
        rc = dtl_writer_add_record(&w, &rec);
        if (rc != DTL_OK)
            return rc;
        imported++;
    }

    if (section_open) {
        rc = dtl_writer_end_section(&w);
        if (rc != DTL_OK)
            return rc;
    }
    rc = dtl_writer_finish(&w, out_bytes, out_len);
    if (rc != DTL_OK)
        return rc;

    if (out_records != NULL)
        *out_records = imported;
    return DTL_OK;
}

dtl_err dtl_import_csv_file(const char *in_path, const char *out_path,
                            size_t max_file, size_t *out_records)
{
    FILE *in;
    FILE *out = NULL;
    dtl_arena a;
    dtl_err rc = DTL_OK;
    long sz;
    size_t n;
    uint8_t *data;
    uint8_t *bytes = NULL;
    size_t out_len = 0;

    if (in_path == NULL || out_path == NULL)
        return DTL_ERR_INVAL;

    in = fopen(in_path, "rb");
    if (in == NULL)
        return DTL_ERR_IO;
    if (fseek(in, 0, SEEK_END) != 0) { fclose(in); return DTL_ERR_IO; }
    sz = ftell(in);
    if (sz < 0 || (unsigned long)sz > max_file) {
        fclose(in);
        return sz < 0 ? DTL_ERR_IO : DTL_ERR_RANGE;
    }
    if (fseek(in, 0, SEEK_SET) != 0) { fclose(in); return DTL_ERR_IO; }

    n = (size_t)sz;
    dtl_arena_init(&a, 256 * 1024);
    data = dtl_arena_alloc(&a, n ? n : 1);
    if (data == NULL) {
        fclose(in);
        dtl_arena_free(&a);
        return DTL_ERR_OOM;
    }
    if (n != 0 && fread(data, 1, n, in) != n) {
        fclose(in);
        dtl_arena_free(&a);
        return DTL_ERR_IO;
    }
    fclose(in);

    rc = dtl_import_csv_memory(data, n, &a, &bytes, &out_len, out_records);
    if (rc != DTL_OK)
        goto done;

    out = fopen(out_path, "wb");
    if (out == NULL) {
        rc = DTL_ERR_IO;
        goto done;
    }
    if (out_len != 0 && fwrite(bytes, 1, out_len, out) != out_len)
        rc = DTL_ERR_IO;

done:
    if (out != NULL)
        fclose(out);
    dtl_arena_free(&a);
    return rc;
}
