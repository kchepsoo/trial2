#include "cli/cli.h"

#include <stdlib.h>
#include <string.h>

#include "codec/registry.h"
#include "core/arena.h"
#include "core/buf.h"
#include "core/err.h"
#include "core/hexdump.h"
#include "format/render.h"
#include "crypto/build_key.h"
#include "crypto/hash.h"
#include "crypto/kdf.h"
#include "crypto/keystore.h"
#include "crypto/redact.h"
#include "format/container.h"
#include "format/tlv.h"
#include "query/query.h"
#include "records/record.h"
#include "records/registry.h"
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

/* ---- small helpers ----------------------------------------------------- */

static int dtl_cli_fail(FILE *err, dtl_err rc)
{
    fprintf(err, "error: %s\n", dtl_strerror(rc));
    return 1;
}

static int dtl_cli_hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int dtl_cli_parse_hex(const char *s, uint8_t *out, size_t out_cap,
                      size_t *out_len)
{
    size_t n = strlen(s);
    size_t bytes;
    size_t i;

    if (n % 2 != 0)
        return -1;
    bytes = n / 2;
    if (bytes > out_cap)
        return -1;

    for (i = 0; i < bytes; i++) {
        int hi = dtl_cli_hexval(s[2 * i]);
        int lo = dtl_cli_hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = bytes;
    return 0;
}

/* Read the whole file at path into an arena buffer, size-capped. */
static dtl_err dtl_cli_read_file(const char *path, dtl_arena *a,
                                 uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long sz;
    size_t n;
    uint8_t *buf = NULL;

    if (f == NULL)
        return DTL_ERR_IO;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return DTL_ERR_IO; }
    sz = ftell(f);
    if (sz < 0) { fclose(f); return DTL_ERR_IO; }
    if ((unsigned long)sz > DTL_CLI_MAX_FILE) { fclose(f); return DTL_ERR_RANGE; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return DTL_ERR_IO; }

    n = (size_t)sz;
    if (n != 0) {
        buf = dtl_arena_alloc(a, n);
        if (buf == NULL) { fclose(f); return DTL_ERR_OOM; }
        if (fread(buf, 1, n, f) != n) { fclose(f); return DTL_ERR_IO; }
    }
    fclose(f);

    *out = buf;
    *out_len = n;
    return DTL_OK;
}

/* ---- stable per-record printing --------------------------------------- */

static const char *dtl_cli_type_name(uint8_t tag)
{
    switch (tag) {
    case DTL_REC_HEARTBEAT: return "HEARTBEAT";
    case DTL_REC_SENSOR:    return "SENSOR";
    case DTL_REC_EVENT:     return "EVENT";
    case DTL_REC_DIAG:      return "DIAG";
    case DTL_REC_GEO:       return "GEO";
    case DTL_REC_BATTERY:   return "BATTERY";
    case DTL_REC_NET:       return "NET";
    case DTL_REC_LOG:       return "LOG";
    case DTL_REC_CONFIG:    return "CONFIG";
    case DTL_REC_KEYREF:    return "KEYREF";
    case DTL_REC_FIRMWARE:  return "FIRMWARE";
    default:                return "UNKNOWN";
    }
}

static void dtl_cli_print_hex(FILE *out, const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        fprintf(out, "%02x", p[i]);
}

static void dtl_cli_print_record(FILE *out, size_t index, const dtl_record *rec)
{
    fprintf(out, "%zu %s", index, dtl_cli_type_name(rec->tag));

    switch (rec->tag) {
    case DTL_REC_HEARTBEAT:
        fprintf(out, " uptime_s=%u seq=%u",
                rec->u.heartbeat.uptime_s, rec->u.heartbeat.seq);
        break;
    case DTL_REC_GEO:
        fprintf(out, " lat_e7=%d lon_e7=%d alt_mm=%d",
                rec->u.geo.lat_e7, rec->u.geo.lon_e7, rec->u.geo.alt_mm);
        break;
    case DTL_REC_BATTERY:
        fprintf(out, " pct=%u temp_c_e1=%d cycles=%u",
                rec->u.battery.pct, rec->u.battery.temp_c_e1,
                rec->u.battery.cycles);
        break;
    case DTL_REC_NET:
        {
            char rxb[16];
            /* Link class follows the parsed interface id. */
            const char *ifkind = rec->u.net.iface_id >= 128 ? "ext" : "int";
            dtl_render_u32(rxb, sizeof rxb, rec->u.net.rx_bytes);
            fprintf(out, " iface_id=%u/%s rx_bytes=%s tx_bytes=%u rx_pkts=%u tx_pkts=%u",
                    rec->u.net.iface_id, ifkind, rxb, rec->u.net.tx_bytes,
                    rec->u.net.rx_pkts, rec->u.net.tx_pkts);
        }
        break;
    case DTL_REC_FIRMWARE:
        fprintf(out, " major=%u minor=%u patch=%u hash=",
                rec->u.firmware.major, rec->u.firmware.minor,
                rec->u.firmware.patch);
        dtl_cli_print_hex(out, rec->u.firmware.hash, 8);
        break;
    case DTL_REC_SENSOR: {
        uint8_t i;
        fprintf(out, " sensor_id=%u count=%u samples=",
                rec->u.sensor.sensor_id, rec->u.sensor.count);
        for (i = 0; i < rec->u.sensor.count; i++) {
            if (i != 0)
                fputc(',', out);
            fprintf(out, "%g", (double)rec->u.sensor.samples[i]);
        }
        break;
    }
    case DTL_REC_EVENT:
        fprintf(out, " code=%u payload_len=%u payload=",
                rec->u.event.code, rec->u.event.payload_len);
        dtl_cli_print_hex(out, rec->u.event.payload, rec->u.event.payload_len);
        break;
    case DTL_REC_LOG:
        fprintf(out, " severity=%u msg_len=%u msg=\"%.*s\"",
                rec->u.log.severity, rec->u.log.msg_len,
                (int)rec->u.log.msg_len, rec->u.log.msg);
        break;
    case DTL_REC_CONFIG: {
        uint8_t i;
        fprintf(out, " pair_count=%u", rec->u.config.pair_count);
        for (i = 0; i < rec->u.config.pair_count; i++)
            fprintf(out, " %s=%s", rec->u.config.pairs[i].key,
                    rec->u.config.pairs[i].value);
        break;
    }
    case DTL_REC_KEYREF:
        fprintf(out, " slot_id=%u label_len=%u label=\"%.*s\" redacted=%u",
                rec->u.keyref.slot_id, rec->u.keyref.label_len,
                (int)rec->u.keyref.label_len, rec->u.keyref.label,
                rec->u.keyref.redacted);
        break;
    case DTL_REC_DIAG:
        fprintf(out, " subsystem=0x%04x blob_len=%u blob=",
                rec->u.diag.subsystem, rec->u.diag.blob_len);
        dtl_cli_print_hex(out, rec->u.diag.blob, rec->u.diag.blob_len);
        fprintf(out, " redacted=%u", rec->u.diag.redacted);
        break;
    default:
        break;
    }
    fputc('\n', out);
}

/* ---- shared decode -> redact -> (filter) -> print ---------------------- */

static int dtl_cli_emit(const dtl_container *cont, dtl_arena *a,
                        FILE *out, FILE *err, const dtl_query *filter)
{
    size_t index = 0;
    uint16_t si;

    for (si = 0; si < cont->section_count; si++) {
        const dtl_section *sec = &cont->sections[si];
        const dtl_codec *codec = dtl_codec_get(sec->codec_id);
        uint8_t *raw;
        dtl_keystore *ks;
        size_t got = 0;
        dtl_buf stream;
        dtl_err rc;

        if (codec == NULL)
            return dtl_cli_fail(err, DTL_ERR_BADRECORD);

        raw = dtl_arena_alloc(a, sec->raw_len);
        if (raw == NULL)
            return dtl_cli_fail(err, DTL_ERR_OOM);
        rc = codec->decode(sec->blob, sec->comp_len, raw, sec->raw_len, &got);
        if (rc != DTL_OK)
            return dtl_cli_fail(err, rc);
        if (got != sec->raw_len)
            return dtl_cli_fail(err, DTL_ERR_BADRECORD);

        /*
         * The device keystore lives right after the section stream, so record
         * parsers can resolve key material without a separate allocation
         * context. It is never emitted: the correct record parsers never
         * overread, and the redaction pass strips secrets before printing.
         */
        ks = dtl_arena_alloc(a, sizeof *ks);
        if (ks == NULL)
            return dtl_cli_fail(err, DTL_ERR_OOM);
        dtl_keystore_init_default(ks);
        /* Provision the session slots (1 and 2) from the device key; KEYREF
         * records resolving to them point at live key material. */
        dtl_kdf_derive(ks->device_key, DTL_KEYSTORE_KEYLEN, ks->slots[1].data);
        ks->slots[1].len = DTL_KEYSTORE_KEYLEN;
        ks->slots[1].used = 1;
        dtl_kdf_derive(ks->slots[1].data, DTL_KEYSTORE_KEYLEN, ks->slots[2].data);
        ks->slots[2].len = DTL_KEYSTORE_KEYLEN;
        ks->slots[2].used = 1;

        dtl_buf_init(&stream, raw, got);
        while (dtl_buf_remaining(&stream) != 0) {
            dtl_tlv tlv;
            dtl_record rec;

            rc = dtl_tlv_next(&stream, &tlv);
            if (rc != DTL_OK)
                return dtl_cli_fail(err, rc);
            rc = dtl_record_parse(&tlv, a, &rec);
            if (rc != DTL_OK) {
                /* Render the offending record bytes for diagnostics. */
                fputs("offending record:\n", err);
                dtl_hexdump(err, tlv.val, tlv.len);
                return dtl_cli_fail(err, rc);
            }

            dtl_redact_record_ks(&rec, ks); /* strip secrets before anything is emitted */

            if (filter == NULL || dtl_query_match(filter, &rec))
                dtl_cli_print_record(out, index, &rec);
            index++;
        }

    }
    return 0;
}

/* ---- subcommands ------------------------------------------------------- */

int dtl_cli_decode(const char *path, FILE *out, FILE *err)
{
    dtl_arena a;
    uint8_t *data;
    size_t len;
    dtl_buf b;
    dtl_container cont;
    dtl_err rc;
    int code;

    dtl_arena_init(&a, 0);
    rc = dtl_cli_read_file(path, &a, &data, &len);
    if (rc != DTL_OK) { dtl_arena_free(&a); return dtl_cli_fail(err, rc); }

    dtl_buf_init(&b, data, len);
    rc = dtl_container_parse(&b, &a, &cont);
    if (rc != DTL_OK) { dtl_arena_free(&a); return dtl_cli_fail(err, rc); }

    code = dtl_cli_emit(&cont, &a, out, err, NULL);
    dtl_arena_free(&a);
    return code;
}

int dtl_cli_query(const char *expr, const char *path, FILE *out, FILE *err)
{
    dtl_arena a;
    uint8_t *data;
    size_t len;
    dtl_buf b;
    dtl_container cont;
    dtl_query *q;
    dtl_err rc;
    int code;

    dtl_arena_init(&a, 0);

    rc = dtl_query_compile(expr, &a, &q);
    if (rc != DTL_OK) { dtl_arena_free(&a); return dtl_cli_fail(err, rc); }

    rc = dtl_cli_read_file(path, &a, &data, &len);
    if (rc != DTL_OK) { dtl_arena_free(&a); return dtl_cli_fail(err, rc); }

    dtl_buf_init(&b, data, len);
    rc = dtl_container_parse(&b, &a, &cont);
    if (rc != DTL_OK) { dtl_arena_free(&a); return dtl_cli_fail(err, rc); }

    code = dtl_cli_emit(&cont, &a, out, err, q);
    dtl_arena_free(&a);
    return code;
}

int dtl_cli_verify(const char *path, const uint8_t *key, size_t key_len,
                   int have_key, FILE *out, FILE *err)
{
    dtl_arena a;
    uint8_t *data;
    size_t len;
    dtl_buf b;
    dtl_container cont;
    dtl_err rc;
    int code;

    dtl_arena_init(&a, 0);
    rc = dtl_cli_read_file(path, &a, &data, &len);
    if (rc != DTL_OK) { dtl_arena_free(&a); return dtl_cli_fail(err, rc); }

    dtl_buf_init(&b, data, len);
    rc = dtl_container_parse(&b, &a, &cont);
    if (rc != DTL_OK) {
        fprintf(out, "verify: bad-container\n");
        dtl_arena_free(&a);
        return 1;
    }

    if (cont.hmac == NULL) {
        fprintf(out, "verify: no-hmac\n");
        code = 0;
    } else if (!have_key) {
        fprintf(out, "verify: no-key\n");
        code = 1;
    } else {
        uint8_t mac[32];
        uint8_t *chk = NULL;
        uint8_t *authenticated;
        const dtl_codec *codec = NULL;
        size_t got = 0;

        /*
         * Integrity spot-check: the first section is decompressed into a
         * scratch buffer, then `authenticated` is allocated immediately after
         * it. The flag is set only by a MAC match below and alone drives the
         * printed verdict.
         */
        if (cont.section_count != 0) {
            codec = dtl_codec_get(cont.sections[0].codec_id);
            chk = dtl_arena_alloc(&a, cont.sections[0].raw_len);
        }
        authenticated = dtl_arena_alloc(&a, 1);
        if (authenticated == NULL || (cont.section_count != 0 && chk == NULL)) {
            dtl_arena_free(&a);
            return dtl_cli_fail(err, DTL_ERR_OOM);
        }
        *authenticated = 0;

        /* MAC covers header + table + blobs, i.e. everything but the trailer. */
        dtl_hash_mac(key, key_len, data, len - 32, mac);
        if (memcmp(mac, cont.hmac, 32) == 0)
            *authenticated = 1;

        /* Decompress the first section to prove it is well-formed. */
        if (codec != NULL) {
            rc = codec->decode(cont.sections[0].blob, cont.sections[0].comp_len,
                               chk, cont.sections[0].raw_len, &got);
            if (rc != DTL_OK)
                *authenticated = 0;
        }

        if (*authenticated) {
            fprintf(out, "verify: OK\n");
            code = 0;
        } else {
            fprintf(out, "verify: FAIL\n");
            code = 1;
        }
    }

    dtl_arena_free(&a);
    return code;
}

int dtl_cli_dump(const char *path, FILE *out, FILE *err)
{
    dtl_arena a;
    uint8_t *data;
    size_t len;
    dtl_buf b;
    dtl_container cont;
    dtl_err rc;
    uint16_t i;

    dtl_arena_init(&a, 0);
    rc = dtl_cli_read_file(path, &a, &data, &len);
    if (rc != DTL_OK) { dtl_arena_free(&a); return dtl_cli_fail(err, rc); }

    dtl_buf_init(&b, data, len);
    rc = dtl_container_parse(&b, &a, &cont);
    if (rc != DTL_OK) { dtl_arena_free(&a); return dtl_cli_fail(err, rc); }

    fprintf(out, "version=%u flags=0x%02x sections=%u hmac=%s\n",
            cont.version, cont.flags, cont.section_count,
            cont.hmac != NULL ? "yes" : "no");
    for (i = 0; i < cont.section_count; i++) {
        const dtl_section *sec = &cont.sections[i];
        fprintf(out, "section %u: type=%u codec=%u raw_len=%u comp_len=%u offset=%u\n",
                i, sec->type, sec->codec_id, sec->raw_len, sec->comp_len,
                sec->offset);
    }

    dtl_arena_free(&a);
    return 0;
}


/* ---- report subcommands ------------------------------------------------- */

int dtl_cli_stats(const char *path, FILE *out, FILE *err)
{
    dtl_stats st;
    dtl_err rc;

    dtl_stats_init(&st);
    rc = dtl_stats_collect_file(path, DTL_CLI_MAX_FILE, &st);
    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    dtl_stats_print(&st, out);
    return 0;
}

int dtl_cli_index(const char *path, FILE *out, FILE *err)
{
    dtl_arena a;
    dtl_index idx;
    dtl_err rc;

    dtl_arena_init(&a, 256 * 1024);
    rc = dtl_index_build(path, DTL_CLI_MAX_FILE, &a, &idx);
    if (rc != DTL_OK) {
        dtl_arena_free(&a);
        return dtl_cli_fail(err, rc);
    }
    dtl_index_print(&idx, out);
    dtl_arena_free(&a);
    return 0;
}

int dtl_cli_export(const char *path, const char *fmt_name, FILE *out,
                   FILE *err)
{
    dtl_export_format fmt;
    dtl_err rc;

    if (dtl_export_parse_format(fmt_name, &fmt) != 0)
        return dtl_cli_fail(err, DTL_ERR_INVAL);
    rc = dtl_export_file(path, DTL_CLI_MAX_FILE, fmt, out);
    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    return 0;
}

int dtl_cli_validate(const char *path, FILE *out, FILE *err)
{
    dtl_arena a;
    dtl_validate_report rep;
    dtl_err rc;

    dtl_arena_init(&a, 256 * 1024);
    rc = dtl_validate_file(path, DTL_CLI_MAX_FILE, &a, &rep);
    if (rc != DTL_OK) {
        dtl_arena_free(&a);
        return dtl_cli_fail(err, rc);
    }
    dtl_validate_print(&rep, out);
    dtl_arena_free(&a);
    return rep.error_count ? 1 : 0;
}

int dtl_cli_diff(const char *path_a, const char *path_b, FILE *out,
                 FILE *err)
{
    size_t diffs = 0;
    dtl_err rc;

    rc = dtl_diff_files(path_a, path_b, DTL_CLI_MAX_FILE, NULL, out, &diffs);
    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    fprintf(out, "diff: %llu record(s) differ\n", (unsigned long long)diffs);
    return diffs ? 1 : 0;
}

int dtl_cli_merge(const char **paths, size_t count, const char *out_path,
                  FILE *out, FILE *err)
{
    dtl_err rc = dtl_merge_files(paths, count, DTL_CLI_MAX_FILE, out_path);

    (void)out;
    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    return 0;
}

int dtl_cli_split(const char *path, const char *out_dir, const char *prefix,
                  FILE *out, FILE *err)
{
    dtl_err rc = dtl_split_file(path, DTL_CLI_MAX_FILE, out_dir, prefix, out);

    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    return 0;
}


int dtl_cli_repack(const char *in_path, const char *out_path,
                   const char *codec_name, FILE *out, FILE *err)
{
    char *end = NULL;
    unsigned long id = strtoul(codec_name, &end, 10);
    dtl_err rc;

    (void)out;
    if (end == codec_name || *end != '\0' || id > 255)
        return dtl_cli_fail(err, DTL_ERR_INVAL);

    rc = dtl_repack_file(in_path, out_path, (uint8_t)id, DTL_CLI_MAX_FILE);
    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    return 0;
}

int dtl_cli_select(const char *expr, const char *in_path,
                   const char *out_path, FILE *out, FILE *err)
{
    size_t kept = 0;
    dtl_err rc = dtl_select_file(in_path, out_path, expr, DTL_CLI_MAX_FILE,
                                 &kept);

    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    fprintf(out, "select: kept %llu record(s)\n", (unsigned long long)kept);
    return 0;
}

int dtl_cli_import(const char *csv_path, const char *out_path, FILE *out,
                   FILE *err)
{
    size_t imported = 0;
    dtl_err rc = dtl_import_csv_file(csv_path, out_path, DTL_CLI_MAX_FILE,
                                     &imported);

    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    fprintf(out, "import: %llu record(s)\n", (unsigned long long)imported);
    return 0;
}


int dtl_cli_import_json(const char *json_path, const char *out_path,
                        FILE *out, FILE *err)
{
    size_t imported = 0;
    dtl_err rc = dtl_import_json_file(json_path, out_path, DTL_CLI_MAX_FILE,
                                      &imported);

    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    fprintf(out, "import: %llu record(s)\n", (unsigned long long)imported);
    return 0;
}

int dtl_cli_timeline(const char *path, FILE *out, FILE *err)
{
    dtl_arena a;
    dtl_timeline tl;
    dtl_err rc;

    dtl_arena_init(&a, 256 * 1024);
    rc = dtl_timeline_build(path, DTL_CLI_MAX_FILE, NULL, &a, &tl);
    if (rc != DTL_OK) {
        dtl_arena_free(&a);
        return dtl_cli_fail(err, rc);
    }
    dtl_timeline_print(&tl, NULL, out);
    dtl_arena_free(&a);
    return 0;
}

int dtl_cli_topk(const char *path, const char *field, const char *n_str,
                 FILE *out, FILE *err)
{
    char *end = NULL;
    unsigned long n = strtoul(n_str, &end, 10);
    dtl_err rc;

    if (end == n_str || *end != '\0')
        return dtl_cli_fail(err, DTL_ERR_INVAL);
    rc = dtl_topk_file(path, DTL_CLI_MAX_FILE, field, (size_t)n, out);
    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    return 0;
}

int dtl_cli_dedup(const char *in_path, const char *out_path, FILE *out,
                  FILE *err)
{
    size_t dropped = 0;
    dtl_err rc = dtl_dedup_file(in_path, out_path, DTL_CLI_MAX_FILE,
                                &dropped);

    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    fprintf(out, "dedup: dropped %llu duplicate record(s)\n",
            (unsigned long long)dropped);
    return 0;
}

int dtl_cli_sample(const char *in_path, const char *out_path,
                   const char *n_str, const char *seed_str, FILE *out,
                   FILE *err)
{
    char *end = NULL;
    unsigned long n = strtoul(n_str, &end, 10);
    unsigned long seed;
    size_t taken = 0;
    dtl_err rc;

    if (end == n_str || *end != '\0')
        return dtl_cli_fail(err, DTL_ERR_INVAL);
    end = NULL;
    seed = strtoul(seed_str, &end, 10);
    if (end == seed_str || *end != '\0' || seed > 0xFFFFFFFFul)
        return dtl_cli_fail(err, DTL_ERR_INVAL);

    rc = dtl_sample_file(in_path, out_path, (size_t)n, (uint32_t)seed,
                         DTL_CLI_MAX_FILE, &taken);
    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    fprintf(out, "sample: took %llu record(s)\n", (unsigned long long)taken);
    return 0;
}

int dtl_cli_sign(const char *in_path, const char *out_path,
                 const uint8_t *key, size_t key_len, FILE *out, FILE *err)
{
    dtl_err rc = dtl_sign_file(in_path, out_path, key, key_len,
                               DTL_CLI_MAX_FILE);

    (void)out;
    if (rc != DTL_OK)
        return dtl_cli_fail(err, rc);
    return 0;
}
