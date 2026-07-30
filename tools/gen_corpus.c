/*
 * tools/gen_corpus -- procedural DTL log generator.
 *
 * Host helper (normal build). Emits a valid DTL container to a path with record
 * values derived from a numeric seed, so tests and solve.sh can build varied,
 * non-hardcoded inputs. Deterministic: the same seed always yields the same
 * file. The log spans a few codecs and deliberately includes a KEYREF and a
 * sensitive DIAG (subsystem 0xFF00), so the stream carries realistic secret-
 * bearing material that the redaction pass must strip on output.
 *
 * Usage: gen_corpus <seed-number> <out-path>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "codec/registry.h"
#include "core/arena.h"
#include "core/err.h"
#include "records/record.h"
#include "writer/writer.h"

static char *adup(dtl_arena *a, const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = dtl_arena_alloc(a, n);
    memcpy(p, s, n);
    return p;
}

static char *afmt(dtl_arena *a, const char *fmt, unsigned v)
{
    char tmp[64];
    snprintf(tmp, sizeof tmp, fmt, v);
    return adup(a, tmp);
}

static int build_corpus(unsigned seed, const char *path)
{
    dtl_arena a;
    dtl_writer w;
    dtl_record r;
    float *samples;
    uint8_t *blob;
    uint8_t *payload;
    dtl_config_pair *pairs;
    uint8_t *bytes;
    size_t len;
    size_t i;
    dtl_err rc;
    int ok;
    FILE *f;

    dtl_arena_init(&a, 0);
    dtl_writer_init(&w, &a);

    /* section 0: store -- heartbeat, geo, battery */
    dtl_writer_begin_section(&w, 1, DTL_CODEC_STORE);
    r.tag = DTL_REC_HEARTBEAT;
    r.u.heartbeat.uptime_s = seed * 100u;
    r.u.heartbeat.seq = seed * 7u + 1u;
    dtl_writer_add_record(&w, &r);
    r.tag = DTL_REC_GEO;
    r.u.geo.lat_e7 = (int32_t)(seed * 1000u);
    r.u.geo.lon_e7 = -(int32_t)(seed * 1000u);
    r.u.geo.alt_mm = (int32_t)seed;
    dtl_writer_add_record(&w, &r);
    r.tag = DTL_REC_BATTERY;
    r.u.battery.pct = (uint8_t)(seed % 100u);
    r.u.battery.temp_c_e1 = (int16_t)((int)(seed * 3u) - 100);
    r.u.battery.cycles = seed * 11u;
    dtl_writer_add_record(&w, &r);
    dtl_writer_end_section(&w);

    /* section 1: lz77 -- keyref (secret label), sensitive diag, event */
    dtl_writer_begin_section(&w, 2, DTL_CODEC_LZ77);
    r.tag = DTL_REC_KEYREF;
    r.u.keyref.slot_id = (uint8_t)(seed % 8u);
    r.u.keyref.label = afmt(&a, "device-key-slot-%u", seed);
    r.u.keyref.label_len = (uint8_t)strlen(r.u.keyref.label);
    r.u.keyref.redacted = 0;
    dtl_writer_add_record(&w, &r);
    r.tag = DTL_REC_DIAG; /* sensitive: key-management subsystem */
    r.u.diag.subsystem = 0xFF00;
    r.u.diag.blob_len = 8;
    blob = dtl_arena_alloc(&a, 8);
    for (i = 0; i < 8; i++)
        blob[i] = (uint8_t)(0x40 + seed + i);
    r.u.diag.blob = blob;
    r.u.diag.redacted = 0;
    dtl_writer_add_record(&w, &r);
    r.tag = DTL_REC_EVENT;
    r.u.event.code = (uint16_t)(seed * 13u);
    r.u.event.payload_len = 4;
    payload = dtl_arena_alloc(&a, 4);
    for (i = 0; i < 4; i++)
        payload[i] = (uint8_t)(seed + i);
    r.u.event.payload = payload;
    dtl_writer_add_record(&w, &r);
    dtl_writer_end_section(&w);

    /* section 2: dict -- log, config, sensor */
    dtl_writer_begin_section(&w, 3, DTL_CODEC_DICT);
    r.tag = DTL_REC_LOG;
    r.u.log.severity = (uint8_t)(seed % 8u);
    r.u.log.msg = afmt(&a, "corpus record seed=%u", seed);
    r.u.log.msg_len = (uint16_t)strlen(r.u.log.msg);
    dtl_writer_add_record(&w, &r);
    r.tag = DTL_REC_CONFIG;
    pairs = dtl_arena_alloc(&a, 2 * sizeof(*pairs));
    pairs[0].key = adup(&a, "mode");
    pairs[0].value = adup(&a, (seed % 2u) == 0 ? "active" : "standby");
    pairs[1].key = adup(&a, "index");
    pairs[1].value = afmt(&a, "%u", seed);
    r.u.config.pair_count = 2;
    r.u.config.pairs = pairs;
    dtl_writer_add_record(&w, &r);
    r.tag = DTL_REC_SENSOR;
    r.u.sensor.sensor_id = (uint16_t)seed;
    r.u.sensor.count = 2;
    samples = dtl_arena_alloc(&a, 2 * sizeof(float));
    samples[0] = 1.5f * (float)seed;
    samples[1] = -2.5f;
    r.u.sensor.samples = samples;
    dtl_writer_add_record(&w, &r);
    dtl_writer_end_section(&w);

    rc = dtl_writer_finish(&w, &bytes, &len);
    if (rc != DTL_OK) {
        fprintf(stderr, "gen_corpus: writer error: %s\n", dtl_strerror(rc));
        dtl_arena_free(&a);
        return 1;
    }

    f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "gen_corpus: cannot write %s\n", path);
        dtl_arena_free(&a);
        return 1;
    }
    ok = (fwrite(bytes, 1, len, f) == len);
    fclose(f);
    dtl_arena_free(&a);

    if (!ok) {
        fprintf(stderr, "gen_corpus: short write to %s\n", path);
        return 1;
    }
    printf("gen_corpus: wrote %s (%zu bytes, seed=%u)\n", path, len, seed);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned long seed;
    char *end;

    if (argc != 3) {
        fprintf(stderr, "usage: gen_corpus <seed-number> <out-path>\n");
        return 2;
    }
    seed = strtoul(argv[1], &end, 10);
    if (*end != '\0') {
        fprintf(stderr, "gen_corpus: seed must be a number\n");
        return 2;
    }
    return build_corpus((unsigned)seed, argv[2]);
}
