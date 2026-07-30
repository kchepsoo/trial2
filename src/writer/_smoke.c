/*
 * _smoke.c (writer) -- write -> read round-trip oracle.
 *
 * Builds logs with several sections using different codecs and a mix of every
 * record type, emits them with the writer, then decodes them back through the
 * full pipeline (container parse -> codec decode -> TLV walk -> record parse) and
 * asserts every record returns field-for-field identical. Also builds a log with
 * an HMAC trailer and re-verifies the MAC. Must run with no sanitizer report in
 * any config.
 *
 * Removed once real tests exist.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "codec/registry.h"
#include "core/arena.h"
#include "core/buf.h"
#include "core/err.h"
#include "crypto/hash.h"
#include "format/container.h"
#include "format/tlv.h"
#include "records/record.h"
#include "records/registry.h"
#include "writer/writer.h"

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

static const uint8_t g_hmac_key[] = "round-trip-key-v1";
#define G_HMAC_KEY_LEN (sizeof g_hmac_key - 1)

/* ---- record construction ---------------------------------------------- */

static char *adup(dtl_arena *a, const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = dtl_arena_alloc(a, n);
    memcpy(p, s, n);
    return p;
}

static char *afmt(dtl_arena *a, const char *fmt, unsigned v)
{
    char tmp[48];
    snprintf(tmp, sizeof tmp, fmt, v);
    return adup(a, tmp);
}

/* Fill r[0..10] with one record of each type, values derived from seed. */
static void make_records(dtl_arena *a, unsigned seed, dtl_record *r)
{
    float *samples;
    uint8_t *bytes;
    dtl_config_pair *pairs;
    size_t i;

    r[0].tag = DTL_REC_HEARTBEAT;
    r[0].u.heartbeat.uptime_s = 1000u * seed + 1u;
    r[0].u.heartbeat.seq = 150u + seed * 7u;

    r[1].tag = DTL_REC_GEO;
    r[1].u.geo.lat_e7 = 100 * (int)seed;
    r[1].u.geo.lon_e7 = -100 * (int)seed;
    r[1].u.geo.alt_mm = (int)seed;

    r[2].tag = DTL_REC_BATTERY;
    r[2].u.battery.pct = (uint8_t)(seed % 100u);
    r[2].u.battery.temp_c_e1 = (int16_t)(-55 + (int)seed);
    r[2].u.battery.cycles = 3u * seed;

    r[3].tag = DTL_REC_NET;
    r[3].u.net.iface_id = (uint8_t)seed;
    r[3].u.net.rx_bytes = 1000u * seed;
    r[3].u.net.tx_bytes = 500u * seed;
    r[3].u.net.rx_pkts = 8u * seed;
    r[3].u.net.tx_pkts = 4u * seed;

    r[4].tag = DTL_REC_FIRMWARE;
    r[4].u.firmware.major = (uint16_t)seed;
    r[4].u.firmware.minor = (uint16_t)(seed + 1u);
    r[4].u.firmware.patch = (uint16_t)(seed + 2u);
    for (i = 0; i < 8; i++)
        r[4].u.firmware.hash[i] = (uint8_t)(seed + i);

    r[5].tag = DTL_REC_SENSOR;
    r[5].u.sensor.sensor_id = (uint16_t)seed;
    r[5].u.sensor.count = 3;
    samples = dtl_arena_alloc(a, 3 * sizeof(float));
    samples[0] = 1.5f * (float)seed;
    samples[1] = -2.25f;
    samples[2] = 3.0e10f + (float)seed;
    r[5].u.sensor.samples = samples;

    r[6].tag = DTL_REC_EVENT;
    r[6].u.event.code = (uint16_t)(seed * 7u);
    r[6].u.event.payload_len = 5;
    bytes = dtl_arena_alloc(a, 5);
    for (i = 0; i < 5; i++)
        bytes[i] = (uint8_t)(seed + i);
    r[6].u.event.payload = bytes;

    r[7].tag = DTL_REC_LOG;
    r[7].u.log.severity = (uint8_t)(seed % 8u);
    r[7].u.log.msg = afmt(a, "log-message-%u", seed);
    r[7].u.log.msg_len = (uint16_t)strlen(r[7].u.log.msg);

    r[8].tag = DTL_REC_CONFIG;
    r[8].u.config.pair_count = 2;
    pairs = dtl_arena_alloc(a, 2 * sizeof(*pairs));
    pairs[0].key = adup(a, "mode");
    pairs[0].value = adup(a, (seed % 2u) == 0 ? "fast" : "slow");
    pairs[1].key = adup(a, "ver");
    pairs[1].value = afmt(a, "1.%u", seed);
    r[8].u.config.pairs = pairs;

    r[9].tag = DTL_REC_KEYREF;
    r[9].u.keyref.slot_id = (uint8_t)(seed % 8u);
    r[9].u.keyref.label = afmt(a, "key-label-%u", seed);
    r[9].u.keyref.label_len = (uint8_t)strlen(r[9].u.keyref.label);
    r[9].u.keyref.redacted = 0;

    r[10].tag = DTL_REC_DIAG;
    r[10].u.diag.subsystem = 0x0042;
    r[10].u.diag.blob_len = 4;
    bytes = dtl_arena_alloc(a, 4);
    for (i = 0; i < 4; i++)
        bytes[i] = (uint8_t)(0xC0 + seed + i);
    r[10].u.diag.blob = bytes;
    r[10].u.diag.redacted = 0;
}

/* ---- field-for-field comparison --------------------------------------- */

static int records_equal(const dtl_record *a, const dtl_record *b)
{
    if (a->tag != b->tag)
        return 0;
    switch (a->tag) {
    case DTL_REC_HEARTBEAT:
        return a->u.heartbeat.uptime_s == b->u.heartbeat.uptime_s &&
               a->u.heartbeat.seq == b->u.heartbeat.seq;
    case DTL_REC_GEO:
        return a->u.geo.lat_e7 == b->u.geo.lat_e7 &&
               a->u.geo.lon_e7 == b->u.geo.lon_e7 &&
               a->u.geo.alt_mm == b->u.geo.alt_mm;
    case DTL_REC_BATTERY:
        return a->u.battery.pct == b->u.battery.pct &&
               a->u.battery.temp_c_e1 == b->u.battery.temp_c_e1 &&
               a->u.battery.cycles == b->u.battery.cycles;
    case DTL_REC_NET:
        return a->u.net.iface_id == b->u.net.iface_id &&
               a->u.net.rx_bytes == b->u.net.rx_bytes &&
               a->u.net.tx_bytes == b->u.net.tx_bytes &&
               a->u.net.rx_pkts == b->u.net.rx_pkts &&
               a->u.net.tx_pkts == b->u.net.tx_pkts;
    case DTL_REC_FIRMWARE:
        return a->u.firmware.major == b->u.firmware.major &&
               a->u.firmware.minor == b->u.firmware.minor &&
               a->u.firmware.patch == b->u.firmware.patch &&
               memcmp(a->u.firmware.hash, b->u.firmware.hash, 8) == 0;
    case DTL_REC_SENSOR:
        return a->u.sensor.sensor_id == b->u.sensor.sensor_id &&
               a->u.sensor.count == b->u.sensor.count &&
               memcmp(a->u.sensor.samples, b->u.sensor.samples,
                      (size_t)a->u.sensor.count * sizeof(float)) == 0;
    case DTL_REC_EVENT:
        return a->u.event.code == b->u.event.code &&
               a->u.event.payload_len == b->u.event.payload_len &&
               (a->u.event.payload_len == 0 ||
                memcmp(a->u.event.payload, b->u.event.payload,
                       a->u.event.payload_len) == 0);
    case DTL_REC_LOG:
        return a->u.log.severity == b->u.log.severity &&
               a->u.log.msg_len == b->u.log.msg_len &&
               strcmp(a->u.log.msg, b->u.log.msg) == 0;
    case DTL_REC_CONFIG: {
        uint8_t i;
        if (a->u.config.pair_count != b->u.config.pair_count)
            return 0;
        for (i = 0; i < a->u.config.pair_count; i++) {
            if (strcmp(a->u.config.pairs[i].key, b->u.config.pairs[i].key) != 0)
                return 0;
            if (strcmp(a->u.config.pairs[i].value, b->u.config.pairs[i].value) != 0)
                return 0;
        }
        return 1;
    }
    case DTL_REC_KEYREF:
        return a->u.keyref.slot_id == b->u.keyref.slot_id &&
               a->u.keyref.label_len == b->u.keyref.label_len &&
               strcmp(a->u.keyref.label, b->u.keyref.label) == 0;
    case DTL_REC_DIAG:
        return a->u.diag.subsystem == b->u.diag.subsystem &&
               a->u.diag.blob_len == b->u.diag.blob_len &&
               (a->u.diag.blob_len == 0 ||
                memcmp(a->u.diag.blob, b->u.diag.blob, a->u.diag.blob_len) == 0);
    default:
        return 0;
    }
}

/* ---- one round-trip run ------------------------------------------------ */

typedef struct {
    uint16_t type;
    uint8_t  codec;
    int      recs[8];
    int      n;
} wgroup;

static void run_roundtrip(const char *name, unsigned seed,
                          const wgroup *groups, size_t ngroups, int use_hmac)
{
    dtl_arena ba;   /* build side: records, writer, emitted bytes */
    dtl_arena ra;   /* read side: parse, decode, re-parsed records */
    dtl_record src[11];
    dtl_writer w;
    int order[64];
    int norder = 0;
    uint8_t *bytes = NULL;
    size_t blen = 0;
    dtl_buf cb;
    dtl_container cont;
    dtl_err rc;
    size_t i;
    int widx = 0;
    int all_ok = 1;

    printf("\n[%s: seed=%u, %zu sections, hmac=%d]\n", name, seed, ngroups, use_hmac);

    dtl_arena_init(&ba, 0);
    dtl_arena_init(&ra, 0);
    make_records(&ba, seed, src);

    dtl_writer_init(&w, &ba);
    for (i = 0; i < ngroups; i++) {
        int j;
        dtl_writer_begin_section(&w, groups[i].type, groups[i].codec);
        for (j = 0; j < groups[i].n; j++) {
            dtl_writer_add_record(&w, &src[groups[i].recs[j]]);
            order[norder++] = groups[i].recs[j];
        }
        dtl_writer_end_section(&w);
    }
    if (use_hmac)
        dtl_writer_set_hmac(&w, g_hmac_key, G_HMAC_KEY_LEN);

    rc = dtl_writer_finish(&w, &bytes, &blen);
    CHECK(rc == DTL_OK, "writer finish OK (%zu bytes, got %s)", blen,
          dtl_strerror(rc));
    if (rc != DTL_OK) {
        dtl_arena_free(&ba);
        dtl_arena_free(&ra);
        return;
    }

    dtl_buf_init(&cb, bytes, blen);
    rc = dtl_container_parse(&cb, &ra, &cont);
    CHECK(rc == DTL_OK, "container parse OK (got %s)", dtl_strerror(rc));
    CHECK(cont.section_count == ngroups, "section_count == %zu (got %u)",
          ngroups, cont.section_count);

    if (rc == DTL_OK && cont.section_count == ngroups) {
        for (i = 0; i < cont.section_count; i++) {
            const dtl_section *sec = &cont.sections[i];
            const dtl_codec *codec = dtl_codec_get(sec->codec_id);
            uint8_t *raw;
            size_t got = 0;
            dtl_buf stream;

            if (codec == NULL) { all_ok = 0; continue; }
            raw = dtl_arena_alloc(&ra, sec->raw_len);
            rc = codec->decode(sec->blob, sec->comp_len, raw, sec->raw_len, &got);
            if (rc != DTL_OK || got != sec->raw_len) { all_ok = 0; continue; }

            dtl_buf_init(&stream, raw, sec->raw_len);
            while (dtl_buf_remaining(&stream) != 0) {
                dtl_tlv tlv;
                dtl_record dec;
                if (dtl_tlv_next(&stream, &tlv) != DTL_OK) { all_ok = 0; break; }
                if (dtl_record_parse(&tlv, &ra, &dec) != DTL_OK) { all_ok = 0; break; }
                if (widx >= norder || !records_equal(&dec, &src[order[widx]]))
                    all_ok = 0;
                widx++;
            }
        }
        CHECK(widx == norder && all_ok,
              "all %d records round-tripped field-for-field", norder);
    }

    if (use_hmac) {
        uint8_t mac[32];
        CHECK(cont.hmac != NULL, "hmac trailer present");
        if (cont.hmac != NULL) {
            dtl_hash_mac(g_hmac_key, G_HMAC_KEY_LEN, bytes, blen - 32, mac);
            CHECK(memcmp(mac, cont.hmac, 32) == 0,
                  "recomputed mac matches trailer");
        }
    }

    dtl_arena_free(&ba);
    dtl_arena_free(&ra);
}

int main(void)
{
    /* Config A: four sections, four codecs, all 11 record types. */
    static const wgroup config_a[] = {
        { 1, DTL_CODEC_STORE, { 0, 2, 1 },     3 }, /* heartbeat, battery, geo */
        { 2, DTL_CODEC_RLE,   { 3, 4 },        2 }, /* net, firmware           */
        { 3, DTL_CODEC_LZ77,  { 5, 6, 7 },     3 }, /* sensor, event, log      */
        { 4, DTL_CODEC_DICT,  { 8, 9, 10 },    3 }  /* config, keyref, diag    */
    };
    /* Config B: three sections, different codec/record mix. */
    static const wgroup config_b[] = {
        { 10, DTL_CODEC_DICT,  { 0, 1, 5, 8 }, 4 }, /* heartbeat, geo, sensor, config */
        { 11, DTL_CODEC_LZ77,  { 2, 3, 6, 9 }, 4 }, /* battery, net, event, keyref    */
        { 12, DTL_CODEC_STORE, { 4, 7, 10 },   3 }  /* firmware, log, diag            */
    };

    printf("writer round-trip oracle\n");

    run_roundtrip("config A", 1, config_a, sizeof config_a / sizeof config_a[0], 0);
    run_roundtrip("config A", 3, config_a, sizeof config_a / sizeof config_a[0], 0);
    run_roundtrip("config B", 2, config_b, sizeof config_b / sizeof config_b[0], 1);
    run_roundtrip("config B", 7, config_b, sizeof config_b / sizeof config_b[0], 1);

    printf("\nwriter smoke: %s (%d failure%s)\n",
           g_failures == 0 ? "ok" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
