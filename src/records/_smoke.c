/*
 * _smoke.c (records) -- throwaway exerciser for records/ (pass 1 + pass 2).
 *
 * Not part of any library. For every record type it builds a valid TLV payload,
 * parses it through the registry, and checks each field (including exact null-
 * termination of string records). It then drives targeted negative paths and,
 * finally, a truncation sweep: every record's valid payload cut to each length
 * in 0..len-1 must be rejected. Every rejection must occur with no ASan/MSan
 * report -- correct rejection, never an over-read.
 *
 * Removed once real tests exist.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/arena.h"
#include "core/endian.h"
#include "core/err.h"
#include "format/tlv.h"
#include "records/record.h"
#include "records/registry.h"

static int g_failures = 0;

#define CHECK(cond, ...)                                        \
    do {                                                        \
        if (cond) {                                             \
            printf("  PASS: ");                                 \
        } else {                                                \
            printf("  FAIL: ");                                 \
            g_failures++;                                       \
        }                                                       \
        printf(__VA_ARGS__);                                    \
        printf("\n");                                           \
    } while (0)

/* Shared expected values so builders and assertions agree bit-for-bit. */
static const float g_sensor_samples[3] = { 1.5f, -2.25f, 3.0e10f };
static const uint8_t g_event_payload[5] = { 1, 2, 3, 4, 5 };
static const char g_log_msg[] = "hello log";       /* 9 chars */
static const char g_keyref_label[] = "sensor-key"; /* 10 chars */
static const uint8_t g_diag_blob[4] = { 0xCA, 0xFE, 0xBA, 0xBE };
static const uint8_t g_firmware_hash[8] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04
};

/*
 * Builders: each fills a caller buffer with a valid payload for one record type
 * and returns its length. Buffers must be at least 32 bytes.
 */
static size_t bld_heartbeat(uint8_t *p)
{
    dtl_endian_write_u32le(p + 0, 123456u);
    dtl_endian_write_u32le(p + 4, 42u);
    return 8;
}
static size_t bld_geo(uint8_t *p)
{
    dtl_endian_write_u32le(p + 0, (uint32_t)374221000);
    dtl_endian_write_u32le(p + 4, (uint32_t)(-1220841000));
    dtl_endian_write_u32le(p + 8, (uint32_t)1500);
    return 12;
}
static size_t bld_battery(uint8_t *p)
{
    p[0] = 87;
    dtl_endian_write_u16le(p + 1, (uint16_t)(int16_t)-55);
    dtl_endian_write_u32le(p + 3, 1200u);
    return 7;
}
static size_t bld_net(uint8_t *p)
{
    p[0] = 2;
    dtl_endian_write_u32le(p + 1, 1000000u);
    dtl_endian_write_u32le(p + 5, 500000u);
    dtl_endian_write_u32le(p + 9, 8000u);
    dtl_endian_write_u32le(p + 13, 4000u);
    return 17;
}
static size_t bld_firmware(uint8_t *p)
{
    dtl_endian_write_u16le(p + 0, 1);
    dtl_endian_write_u16le(p + 2, 2);
    dtl_endian_write_u16le(p + 4, 3);
    memcpy(p + 6, g_firmware_hash, 8);
    return 14;
}
static size_t bld_sensor(uint8_t *p)
{
    size_t i;
    dtl_endian_write_u16le(p + 0, 0x1234);
    p[2] = 3;
    for (i = 0; i < 3; i++) {
        uint32_t bits;
        memcpy(&bits, &g_sensor_samples[i], sizeof bits);
        dtl_endian_write_u32le(p + 3 + i * 4, bits);
    }
    return 3 + 3 * 4;
}
static size_t bld_event(uint8_t *p)
{
    dtl_endian_write_u16le(p + 0, 0x00AB);
    dtl_endian_write_u16le(p + 2, (uint16_t)sizeof g_event_payload);
    memcpy(p + 4, g_event_payload, sizeof g_event_payload);
    return 4 + sizeof g_event_payload;
}
static size_t bld_log(uint8_t *p)
{
    size_t n = sizeof g_log_msg - 1; /* exclude the source literal's NUL */
    p[0] = 3;
    dtl_endian_write_u16le(p + 1, (uint16_t)n);
    memcpy(p + 3, g_log_msg, n);
    return 3 + n;
}
static size_t bld_config(uint8_t *p)
{
    size_t o = 0;
    p[o++] = 2; /* pair_count */
    p[o++] = 3; memcpy(p + o, "ver", 3);  o += 3;
    p[o++] = 3; memcpy(p + o, "1.0", 3);  o += 3;
    p[o++] = 4; memcpy(p + o, "mode", 4); o += 4;
    p[o++] = 4; memcpy(p + o, "fast", 4); o += 4;
    return o;
}
static size_t bld_keyref(uint8_t *p)
{
    size_t n = sizeof g_keyref_label - 1;
    p[0] = 5;
    p[1] = (uint8_t)n;
    memcpy(p + 2, g_keyref_label, n);
    return 2 + n;
}
static size_t bld_diag(uint8_t *p)
{
    dtl_endian_write_u16le(p + 0, 0x0042);
    dtl_endian_write_u16le(p + 2, (uint16_t)sizeof g_diag_blob);
    memcpy(p + 4, g_diag_blob, sizeof g_diag_blob);
    return 4 + sizeof g_diag_blob;
}

int main(void)
{
    dtl_arena arena;
    dtl_arena_init(&arena, 0);

    /* --- REC_HEARTBEAT (0x10) -------------------------------------------- */
    printf("[REC_HEARTBEAT 0x10]\n");
    {
        uint8_t p[8];
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;

        dtl_endian_write_u32le(p + 0, 123456u);
        dtl_endian_write_u32le(p + 4, 42u);
        tlv.tag = DTL_REC_HEARTBEAT;
        tlv.len = sizeof p;
        tlv.val = p;

        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_OK, "parse OK (got %s)", dtl_strerror(rc));
        CHECK(r.tag == DTL_REC_HEARTBEAT, "tag 0x10");
        CHECK(r.u.heartbeat.uptime_s == 123456u, "uptime_s == 123456 (got %u)",
              r.u.heartbeat.uptime_s);
        CHECK(r.u.heartbeat.seq == 42u, "seq == 42 (got %u)", r.u.heartbeat.seq);
    }

    /* --- REC_GEO (0x14) -------------------------------------------------- */
    printf("\n[REC_GEO 0x14]\n");
    {
        uint8_t p[12];
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;

        dtl_endian_write_u32le(p + 0, (uint32_t)374221000);   /* 37.4221 deg  */
        dtl_endian_write_u32le(p + 4, (uint32_t)(-1220841000)); /* -122.0841  */
        dtl_endian_write_u32le(p + 8, (uint32_t)1500);        /* 1500 mm      */
        tlv.tag = DTL_REC_GEO;
        tlv.len = sizeof p;
        tlv.val = p;

        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_OK, "parse OK (got %s)", dtl_strerror(rc));
        CHECK(r.u.geo.lat_e7 == 374221000, "lat_e7 == 374221000 (got %d)",
              r.u.geo.lat_e7);
        CHECK(r.u.geo.lon_e7 == -1220841000, "lon_e7 == -1220841000 (got %d)",
              r.u.geo.lon_e7);
        CHECK(r.u.geo.alt_mm == 1500, "alt_mm == 1500 (got %d)", r.u.geo.alt_mm);
    }

    /* --- REC_BATTERY (0x15) ---------------------------------------------- */
    printf("\n[REC_BATTERY 0x15]\n");
    {
        uint8_t p[7];
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;

        p[0] = 87;                                    /* pct */
        dtl_endian_write_u16le(p + 1, (uint16_t)(int16_t)-55); /* -5.5 C */
        dtl_endian_write_u32le(p + 3, 1200u);         /* cycles */
        tlv.tag = DTL_REC_BATTERY;
        tlv.len = sizeof p;
        tlv.val = p;

        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_OK, "parse OK (got %s)", dtl_strerror(rc));
        CHECK(r.u.battery.pct == 87, "pct == 87 (got %u)", r.u.battery.pct);
        CHECK(r.u.battery.temp_c_e1 == -55, "temp_c_e1 == -55 (got %d)",
              r.u.battery.temp_c_e1);
        CHECK(r.u.battery.cycles == 1200u, "cycles == 1200 (got %u)",
              r.u.battery.cycles);
    }

    /* --- REC_FIRMWARE (0x1A) --------------------------------------------- */
    printf("\n[REC_FIRMWARE 0x1A]\n");
    {
        static const uint8_t hash[8] = {
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04
        };
        uint8_t p[14];
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;

        dtl_endian_write_u16le(p + 0, 1);
        dtl_endian_write_u16le(p + 2, 2);
        dtl_endian_write_u16le(p + 4, 3);
        memcpy(p + 6, hash, 8);
        tlv.tag = DTL_REC_FIRMWARE;
        tlv.len = sizeof p;
        tlv.val = p;

        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_OK, "parse OK (got %s)", dtl_strerror(rc));
        CHECK(r.u.firmware.major == 1 && r.u.firmware.minor == 2 &&
              r.u.firmware.patch == 3, "version == 1.2.3 (got %u.%u.%u)",
              r.u.firmware.major, r.u.firmware.minor, r.u.firmware.patch);
        CHECK(memcmp(r.u.firmware.hash, hash, 8) == 0, "hash matches");
    }

    /* --- REC_NET (0x16) -------------------------------------------------- */
    printf("\n[REC_NET 0x16]\n");
    {
        uint8_t p[17];
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;

        p[0] = 2;                                 /* iface_id */
        dtl_endian_write_u32le(p + 1, 1000000u);  /* rx_bytes */
        dtl_endian_write_u32le(p + 5, 500000u);   /* tx_bytes */
        dtl_endian_write_u32le(p + 9, 8000u);     /* rx_pkts  */
        dtl_endian_write_u32le(p + 13, 4000u);    /* tx_pkts  */
        tlv.tag = DTL_REC_NET;
        tlv.len = sizeof p;
        tlv.val = p;

        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_OK, "parse OK (got %s)", dtl_strerror(rc));
        CHECK(r.u.net.iface_id == 2, "iface_id == 2 (got %u)", r.u.net.iface_id);
        CHECK(r.u.net.rx_bytes == 1000000u, "rx_bytes == 1000000 (got %u)",
              r.u.net.rx_bytes);
        CHECK(r.u.net.tx_bytes == 500000u, "tx_bytes == 500000 (got %u)",
              r.u.net.tx_bytes);
        CHECK(r.u.net.rx_pkts == 8000u, "rx_pkts == 8000 (got %u)",
              r.u.net.rx_pkts);
        CHECK(r.u.net.tx_pkts == 4000u, "tx_pkts == 4000 (got %u)",
              r.u.net.tx_pkts);
    }

    /* --- malformed lengths: every parser must reject len != expected ----- */
    printf("\n[malformed payload lengths]\n");
    {
        struct { uint8_t tag; uint16_t size; const char *name; } specs[] = {
            { DTL_REC_HEARTBEAT, 8,  "heartbeat" },
            { DTL_REC_GEO,       12, "geo" },
            { DTL_REC_BATTERY,   7,  "battery" },
            { DTL_REC_NET,       17, "net" },
            { DTL_REC_FIRMWARE,  14, "firmware" }
        };
        size_t i;
        uint8_t buf[32];

        memset(buf, 0xA5, sizeof buf);

        for (i = 0; i < sizeof specs / sizeof specs[0]; i++) {
            dtl_tlv tlv;
            dtl_record r;
            dtl_err rc;

            tlv.tag = specs[i].tag;
            tlv.val = buf;

            tlv.len = (uint16_t)(specs[i].size - 1); /* too short */
            rc = dtl_record_parse(&tlv, &arena, &r);
            CHECK(rc == DTL_ERR_BADRECORD, "%s too-short -> BADRECORD (got %s)",
                  specs[i].name, dtl_strerror(rc));

            tlv.len = (uint16_t)(specs[i].size + 1); /* too long */
            rc = dtl_record_parse(&tlv, &arena, &r);
            CHECK(rc == DTL_ERR_BADRECORD, "%s too-long -> BADRECORD (got %s)",
                  specs[i].name, dtl_strerror(rc));
        }
    }

    /* --- unknown tag ----------------------------------------------------- */
    printf("\n[unknown tag]\n");
    {
        uint8_t buf[8] = { 0 };
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;

        tlv.tag = 0x99; /* not a registered record type */
        tlv.len = sizeof buf;
        tlv.val = buf;

        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_ERR_BADRECORD, "unknown tag 0x99 -> BADRECORD (got %s)",
              dtl_strerror(rc));
    }

    /* --- REC_SENSOR (0x11) ----------------------------------------------- */
    printf("\n[REC_SENSOR 0x11]\n");
    {
        uint8_t p[64];
        size_t n = bld_sensor(p);
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;
        int ok = 1;
        size_t i;

        tlv.tag = DTL_REC_SENSOR;
        tlv.len = (uint16_t)n;
        tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_OK, "parse OK (got %s)", dtl_strerror(rc));
        CHECK(r.u.sensor.sensor_id == 0x1234, "sensor_id == 0x1234 (got 0x%04x)",
              r.u.sensor.sensor_id);
        CHECK(r.u.sensor.count == 3, "count == 3 (got %u)", r.u.sensor.count);
        for (i = 0; i < 3; i++)
            if (r.u.sensor.samples[i] != g_sensor_samples[i])
                ok = 0;
        CHECK(ok, "samples decode to {1.5, -2.25, 3e10} (bit-exact)");
    }

    /* --- REC_EVENT (0x12) ------------------------------------------------ */
    printf("\n[REC_EVENT 0x12]\n");
    {
        uint8_t p[64];
        size_t n = bld_event(p);
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;

        tlv.tag = DTL_REC_EVENT;
        tlv.len = (uint16_t)n;
        tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_OK, "parse OK (got %s)", dtl_strerror(rc));
        CHECK(r.u.event.code == 0x00AB, "code == 0x00AB (got 0x%04x)",
              r.u.event.code);
        CHECK(r.u.event.payload_len == sizeof g_event_payload,
              "payload_len == 5 (got %u)", r.u.event.payload_len);
        CHECK(r.u.event.payload != NULL &&
              memcmp(r.u.event.payload, g_event_payload,
                     sizeof g_event_payload) == 0, "payload matches");
    }

    /* --- REC_LOG (0x17) -------------------------------------------------- */
    printf("\n[REC_LOG 0x17]\n");
    {
        uint8_t p[64];
        size_t n = bld_log(p);
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;

        tlv.tag = DTL_REC_LOG;
        tlv.len = (uint16_t)n;
        tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_OK, "parse OK (got %s)", dtl_strerror(rc));
        CHECK(r.u.log.severity == 3, "severity == 3 (got %u)", r.u.log.severity);
        CHECK(r.u.log.msg_len == 9, "msg_len == 9 (got %u)", r.u.log.msg_len);
        CHECK(r.u.log.msg != NULL && strcmp(r.u.log.msg, g_log_msg) == 0,
              "msg == \"hello log\"");
        CHECK(r.u.log.msg != NULL && strlen(r.u.log.msg) == 9,
              "msg is null-terminated at exactly 9 (no over-read by one)");
    }

    /* --- REC_CONFIG (0x18) ----------------------------------------------- */
    printf("\n[REC_CONFIG 0x18]\n");
    {
        uint8_t p[64];
        size_t n = bld_config(p);
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;

        tlv.tag = DTL_REC_CONFIG;
        tlv.len = (uint16_t)n;
        tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_OK, "parse OK (got %s)", dtl_strerror(rc));
        CHECK(r.u.config.pair_count == 2, "pair_count == 2 (got %u)",
              r.u.config.pair_count);
        if (rc == DTL_OK && r.u.config.pair_count == 2) {
            CHECK(strcmp(r.u.config.pairs[0].key, "ver") == 0 &&
                  strcmp(r.u.config.pairs[0].value, "1.0") == 0,
                  "pair 0 == ver=1.0");
            CHECK(strcmp(r.u.config.pairs[1].key, "mode") == 0 &&
                  strcmp(r.u.config.pairs[1].value, "fast") == 0,
                  "pair 1 == mode=fast");
        }
    }

    /* --- REC_KEYREF (0x19) ----------------------------------------------- */
    printf("\n[REC_KEYREF 0x19]\n");
    {
        uint8_t p[64];
        size_t n = bld_keyref(p);
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;

        tlv.tag = DTL_REC_KEYREF;
        tlv.len = (uint16_t)n;
        tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_OK, "parse OK (got %s)", dtl_strerror(rc));
        CHECK(r.u.keyref.slot_id == 5, "slot_id == 5 (got %u)",
              r.u.keyref.slot_id);
        CHECK(r.u.keyref.label_len == 10, "label_len == 10 (got %u)",
              r.u.keyref.label_len);
        CHECK(r.u.keyref.label != NULL &&
              strcmp(r.u.keyref.label, g_keyref_label) == 0,
              "label == \"sensor-key\"");
    }

    /* --- REC_DIAG (0x13) ------------------------------------------------- */
    printf("\n[REC_DIAG 0x13]\n");
    {
        uint8_t p[64];
        size_t n = bld_diag(p);
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;

        tlv.tag = DTL_REC_DIAG;
        tlv.len = (uint16_t)n;
        tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_OK, "parse OK (got %s)", dtl_strerror(rc));
        CHECK(r.u.diag.subsystem == 0x0042, "subsystem == 0x0042 (got 0x%04x)",
              r.u.diag.subsystem);
        CHECK(r.u.diag.blob_len == sizeof g_diag_blob, "blob_len == 4 (got %u)",
              r.u.diag.blob_len);
        CHECK(r.u.diag.blob != NULL &&
              memcmp(r.u.diag.blob, g_diag_blob, sizeof g_diag_blob) == 0,
              "blob matches");
    }

    /* --- pass-2 targeted negative paths ---------------------------------- */
    printf("\n[pass-2 negative paths]\n");
    {
        uint8_t p[64];
        dtl_tlv tlv;
        dtl_record r;
        dtl_err rc;
        size_t n;

        /* sensor: count says 3 (12 bytes) but only 8 bytes of samples. */
        dtl_endian_write_u16le(p + 0, 0x1234);
        p[2] = 3;
        memset(p + 3, 0, 8);
        n = 3 + 8;
        tlv.tag = DTL_REC_SENSOR; tlv.len = (uint16_t)n; tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_ERR_BADRECORD,
              "sensor count*4 != remaining -> BADRECORD (got %s)",
              dtl_strerror(rc));

        /* event: payload_len 10 but only 3 bytes remain (too big). */
        dtl_endian_write_u16le(p + 0, 0x00AB);
        dtl_endian_write_u16le(p + 2, 10);
        memset(p + 4, 0, 3);
        n = 4 + 3;
        tlv.tag = DTL_REC_EVENT; tlv.len = (uint16_t)n; tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_ERR_BADRECORD,
              "event payload_len too-big -> BADRECORD (got %s)", dtl_strerror(rc));

        /* event: payload_len 1 but 5 bytes remain (too small). */
        dtl_endian_write_u16le(p + 0, 0x00AB);
        dtl_endian_write_u16le(p + 2, 1);
        memset(p + 4, 0, 5);
        n = 4 + 5;
        tlv.tag = DTL_REC_EVENT; tlv.len = (uint16_t)n; tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_ERR_BADRECORD,
              "event payload_len too-small -> BADRECORD (got %s)",
              dtl_strerror(rc));

        /* log: severity 9 (> 7). */
        p[0] = 9;
        dtl_endian_write_u16le(p + 1, 3);
        memset(p + 3, 0, 3);
        n = 3 + 3;
        tlv.tag = DTL_REC_LOG; tlv.len = (uint16_t)n; tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_ERR_BADRECORD, "log severity>7 -> BADRECORD (got %s)",
              dtl_strerror(rc));

        /* log: msg_len 10 but only 3 bytes remain. */
        p[0] = 1;
        dtl_endian_write_u16le(p + 1, 10);
        memset(p + 3, 0, 3);
        n = 3 + 3;
        tlv.tag = DTL_REC_LOG; tlv.len = (uint16_t)n; tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_ERR_BADRECORD, "log msg_len mismatch -> BADRECORD (got %s)",
              dtl_strerror(rc));

        /* config: pair 0 klen 200 runs past the TLV. */
        p[0] = 2;
        p[1] = 200;
        memset(p + 2, 0, 3);
        n = 2 + 3;
        tlv.tag = DTL_REC_CONFIG; tlv.len = (uint16_t)n; tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_ERR_TRUNCATED, "config pair past end -> TRUNCATED (got %s)",
              dtl_strerror(rc));

        /* keyref: label_len 50 runs past the TLV. */
        p[0] = 5;
        p[1] = 50;
        memset(p + 2, 0, 3);
        n = 2 + 3;
        tlv.tag = DTL_REC_KEYREF; tlv.len = (uint16_t)n; tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_ERR_TRUNCATED, "keyref label past end -> TRUNCATED (got %s)",
              dtl_strerror(rc));

        /* diag: blob_len 10 but only 4 bytes remain (too big). */
        dtl_endian_write_u16le(p + 0, 0x0042);
        dtl_endian_write_u16le(p + 2, 10);
        memset(p + 4, 0, 4);
        n = 4 + 4;
        tlv.tag = DTL_REC_DIAG; tlv.len = (uint16_t)n; tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_ERR_BADRECORD,
              "diag blob_len too-big -> BADRECORD (got %s)", dtl_strerror(rc));

        /* diag: blob_len 1 but 4 bytes remain (too small). */
        dtl_endian_write_u16le(p + 0, 0x0042);
        dtl_endian_write_u16le(p + 2, 1);
        memset(p + 4, 0, 4);
        n = 4 + 4;
        tlv.tag = DTL_REC_DIAG; tlv.len = (uint16_t)n; tlv.val = p;
        rc = dtl_record_parse(&tlv, &arena, &r);
        CHECK(rc == DTL_ERR_BADRECORD,
              "diag blob_len too-small -> BADRECORD (got %s)", dtl_strerror(rc));
    }

    /* --- truncation sweep: every valid payload cut to 0..len-1 ----------- */
    printf("\n[truncation sweep across all record types]\n");
    {
        struct {
            uint8_t tag;
            size_t (*build)(uint8_t *);
            const char *name;
        } fz[] = {
            { DTL_REC_HEARTBEAT, bld_heartbeat, "heartbeat" },
            { DTL_REC_GEO,       bld_geo,       "geo" },
            { DTL_REC_BATTERY,   bld_battery,   "battery" },
            { DTL_REC_NET,       bld_net,       "net" },
            { DTL_REC_FIRMWARE,  bld_firmware,  "firmware" },
            { DTL_REC_SENSOR,    bld_sensor,    "sensor" },
            { DTL_REC_EVENT,     bld_event,     "event" },
            { DTL_REC_LOG,       bld_log,       "log" },
            { DTL_REC_CONFIG,    bld_config,    "config" },
            { DTL_REC_KEYREF,    bld_keyref,    "keyref" },
            { DTL_REC_DIAG,      bld_diag,      "diag" }
        };
        size_t f;

        for (f = 0; f < sizeof fz / sizeof fz[0]; f++) {
            uint8_t p[64];
            size_t full = fz[f].build(p);
            size_t l;
            size_t rejected = 0;

            for (l = 0; l < full; l++) {
                dtl_tlv tlv;
                dtl_record r;
                dtl_err rc;

                tlv.tag = fz[f].tag;
                tlv.len = (uint16_t)l;
                tlv.val = p;
                rc = dtl_record_parse(&tlv, &arena, &r);
                if (rc != DTL_OK)
                    rejected++;
                dtl_arena_reset(&arena); /* keep arena bounded across the sweep */
            }

            CHECK(rejected == full,
                  "%s: all %zu truncations (len 0..%zu) rejected",
                  fz[f].name, full, full - 1);
        }
    }

    dtl_arena_free(&arena);

    printf("\nrecords smoke: %s (%d failure%s)\n",
           g_failures == 0 ? "ok" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
