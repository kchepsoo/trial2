#include "cli/cli.h"

#include <string.h>

#include "defects.h"
#if DTL_BUG(1) || DTL_BUG(2) || DTL_BUG(20) || DTL_BUG(21) || DTL_BUG(36)
#include <stdlib.h>
#endif
#if DTL_BUG(2)
#include <malloc.h>
#endif

#if DTL_BUG(2) || DTL_BUG(21)
/* Sanitizer builds use their own allocators: chunk geometry differs from the
 * libc layout the crafted section assumes, but the redzone/interceptor fires
 * regardless of layout, so grooming only runs in the plain build. */
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_MEMORY__)
#define DTL_CLI_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer)
#define DTL_CLI_SANITIZED 1
#endif
#endif
#ifndef DTL_CLI_SANITIZED
#define DTL_CLI_SANITIZED 0
#endif
#endif /* DTL_BUG(2) || DTL_BUG(21) */

#ifdef DTL_DEBUG_LAYOUT
#include <malloc.h>
#endif

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
#include "defects.h"
#include "format/container.h"
#include "format/tlv.h"
#include "query/query.h"
#include "records/record.h"
#include "records/registry.h"

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
#if DTL_BUG(1)
    dtl_keystore *ks_leak_guard = NULL;
#endif

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

#if DTL_BUG(1)
        /*
         * BUG 1 backing store: the section stream is a dedicated, tightly
         * sized heap block (not arena-carved), so a record parser that
         * overreads the stream crosses a real malloc redzone -- ASan reports a
         * genuine heap-buffer-overflow before the read reaches the key bytes.
         */
        raw = malloc(sec->raw_len);
#elif DTL_BUG(36)
        /*
         * BUG 36: the staging buffer handed to the decoder is sized by the
         * COMPRESSED length while the decoder is told it holds raw_len
         * bytes -- the two lengths cross the container/codec boundary in
         * the wrong slots, and any section that compresses at all overflows
         * the handoff buffer. Tight heap block so ASan sees the crossing.
         */
        raw = malloc(sec->comp_len);
#else
        raw = dtl_arena_alloc(a, sec->raw_len);
#endif
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
#if DTL_BUG(1)
        /* BUG 1 backing store: a second tight heap block immediately
         * after the stream, so a non-instrumented overread lands on the
         * device key at a deterministic offset. */
        ks = malloc(sizeof *ks);
#elif DTL_BUG(21)
        /* BUG 21 backing store: the keystore is a private malloc so its
         * early release is a real free(). */
        ks = malloc(sizeof *ks);
#else
        ks = dtl_arena_alloc(a, sizeof *ks);
#endif
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
#if DTL_BUG(1)
        ks_leak_guard = ks;
#endif
#if DTL_BUG(21)
        /* BUG 21: the keystore is released right after provisioning, before
         * the emit pass whose redaction consults it. The session table is
         * immediately re-provisioned zeroed, so through the stale pointer
         * every slot reads as unused and redaction is silently skipped. */
        {
            /* Free through an opaque pointer so the stale keystore is
             * genuinely re-read after release. The session table is then
             * allocated by grooming until it recycles the freed block, so
             * through the stale pointer every slot reads as unused and
             * redaction is silently skipped. (Sanitizer builds use their
             * own allocator: the redzone fires on the stale read without
             * any grooming, so the loop stops immediately there.) */
            void (*volatile release)(void *) = free;
            static void *holders[512];
            void *session;
            size_t h = 0;
            release(ks);
            for (;;) {
                session = malloc(sizeof *ks);
#if DTL_CLI_SANITIZED
                break;
#else
                if (session == NULL || session == ks)
                    break;
                holders[h++ % 512u] = session; /* leak the losers */
#endif
            }
            if (session == ks)
                memset(session, 0, sizeof *ks); /* leaked session table */
        }
#endif

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
#if DTL_BUG(20)
                /* BUG 20: the diagnostic scratch is a private malloc that is
                 * released before the handler renders the offending bytes
                 * from it. */
                uint8_t *scratch = malloc((size_t)tlv.len + 16u);
                if (scratch != NULL) {
                    char *banner;
                    memcpy(scratch, tlv.val, tlv.len);
                    free(scratch);
                    /* The error banner is formatted between the free and the
                     * render; its allocation recycles the scratch block, so
                     * the dump shows banner bytes instead of the record. */
                    banner = malloc((size_t)tlv.len + 16u);
                    if (banner != NULL) {
                        memcpy(banner, "offending record:", 17);
                        banner[17] = '\0';
                        fputs(banner, err);
                        fputc('\n', err);
                    }
                    dtl_hexdump(err, scratch, tlv.len);
                }
#else
                fputs("offending record:\n", err);
                dtl_hexdump(err, tlv.val, tlv.len);
#endif
                return dtl_cli_fail(err, rc);
            }

#if DTL_BUG(37)
            /* BUG 37: emission happens BEFORE the redaction pass, so secret
             * fields are printed in the clear; the record is scrubbed only
             * afterwards, when nothing consults it any more. */
            if (filter == NULL || dtl_query_match(filter, &rec))
                dtl_cli_print_record(out, index, &rec);
            dtl_redact_record_ks(&rec, ks);
            index++;
#else
            dtl_redact_record_ks(&rec, ks); /* strip secrets before anything is emitted */

            if (filter == NULL || dtl_query_match(filter, &rec))
                dtl_cli_print_record(out, index, &rec);
            index++;
#endif
        }

#if DTL_BUG(1)
        /* Section fully emitted; release the dedicated heap blocks. */
        free(ks_leak_guard);
        ks_leak_guard = NULL;
        free(raw);
#endif
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
#if DTL_BUG(2)
            /*
             * BUG 2: the decompression buffer is sized by comp_len while the
             * codec still decodes raw_len bytes -- a crafted section writes
             * past the buffer into the flag allocated next. Both blocks are
             * dedicated tight heap allocations (not arena-carved), so the
             * overflow crosses a real malloc redzone -- ASan reports a genuine
             * heap-buffer-overflow -- while a non-instrumented build writes
             * onward into the adjacent flag block.
             *
             * Layout grooming: re-allocate the pair until the allocator
             * places them back to back with the exact chunk geometry the
             * crafted section assumes -- both chunks 0x20 bytes (24 usable),
             * flag data one chunk (32 bytes) past the scratch base, so the
             * overflow rewrites the flag chunk's size field with its own
             * valid value and then flips the flag. Rejected pairs are leaked
             * (single-shot CLI); the allocator's bins hold finitely many
             * candidates, after which fresh top chunks are adjacent.
             */
            for (;;) {
                chk = malloc(cont.sections[0].comp_len);
                authenticated = malloc(1);
                if (chk == NULL || authenticated == NULL)
                    break; /* OOM: handled by the check below */
#if DTL_CLI_SANITIZED
                break; /* sanitized allocator: the report fires on any layout */
#else
                if (malloc_usable_size(chk) == 24 &&
                    malloc_usable_size(authenticated) == 24 &&
                    (char *)authenticated - (char *)chk == 32)
                    break;
#endif
            }
#else
            chk = dtl_arena_alloc(&a, cont.sections[0].raw_len);
#endif
        }
#if DTL_BUG(2)
        if (cont.section_count == 0)
            authenticated = malloc(1);
#else
        authenticated = dtl_arena_alloc(&a, 1);
#endif
        if (authenticated == NULL || (cont.section_count != 0 && chk == NULL)) {
            dtl_arena_free(&a);
            return dtl_cli_fail(err, DTL_ERR_OOM);
        }
        *authenticated = 0;
#ifdef DTL_DEBUG_LAYOUT
        fprintf(stderr, "DBG chk=%p auth=%p diff=%ld usable_chk=%zu usable_auth=%zu\n",
                (void*)chk, (void*)authenticated, (long)((char*)authenticated-(char*)chk),
                malloc_usable_size(chk), malloc_usable_size(authenticated));
#endif

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
#if DTL_BUG(2)
        /*
         * The blocks are deliberately not freed: the crafted overflow rewrites
         * the flag chunk's header on its way to the flag byte, so passing the
         * flag pointer back to free() would trip the allocator's consistency
         * checks. The CLI is single-shot; the arena teardown below releases
         * everything else.
         */
#endif
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
